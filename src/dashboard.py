#!/usr/bin/env python3
"""
dashboard.py - Tableau de bord du mini IDS (projet 10).

Formulaire de 7 caracteristiques -> verdict de la foret aleatoire + probabilites,
avec la matrice de confusion et l'importance des variables.

La page ne contient AUCUNE cle d'API : le modele est charge cote serveur (Flask)
et le navigateur ne parle qu'a ce serveur local.

Usage (depuis le dossier tp-ia-ids, .venv actif, apres entrainer.py) :
    python src\\dashboard.py
puis ouvrir http://127.0.0.1:5002
"""
import os

import joblib
import pandas as pd
from flask import Flask, jsonify, request, send_from_directory

if not os.path.exists("modele/foret.joblib"):
    raise SystemExit("Modele introuvable : lancez d'abord python src\\entrainer.py "
                     "(depuis le dossier tp-ia-ids).")

paquet = joblib.load("modele/foret.joblib")
MODELE = paquet["modele"]
CARACTERISTIQUES = paquet["caracteristiques"]

BORNES = {
    "nb_connexions": (0, 1_000_000),
    "nb_ports_distincts": (0, 65535),
    "paquets_par_s": (0, 10_000_000),
    "taille_moy_paquet": (0, 65535),
    "taux_syn_sans_ack": (0, 1),
    "taux_echec_auth": (0, 1),
    "duree_moy_s": (0, 86400),
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096

PAGE = r"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Détecteur d’intrusion réseau</title>
<style>
:root{
  color-scheme: light dark;
  --fond:#eef1f4; --carte:#ffffff; --encre:#18222d; --discret:#5b6875; --trait:#d3d9e0;
  --normal:#1b7f6b; --alerte:#b3261e; --accent:#2a4d8f; --champ:#f7f9fb;
}
@media (prefers-color-scheme: dark){
  :root{ --fond:#12181f; --carte:#1b232c; --encre:#e6ebf0; --discret:#97a4b1; --trait:#2d3945;
         --normal:#4cc2a8; --alerte:#ff8a80; --accent:#8fb0f0; --champ:#141b22; }
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--fond);color:var(--encre);font:16px/1.5 "Segoe UI",system-ui,sans-serif;padding:24px}
main{max-width:1080px;margin:0 auto}
h1{font-size:1.6rem;margin:0 0 4px}
.sous{color:var(--discret);margin:0 0 24px;max-width:60ch}
.grille{display:grid;grid-template-columns:minmax(280px,380px) 1fr;gap:20px;align-items:start}
@media (max-width:820px){.grille{grid-template-columns:1fr}}
section{background:var(--carte);border:1px solid var(--trait);border-radius:10px;padding:20px}
h2{font-size:1.05rem;margin:0 0 12px}
.presets{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
button{font:inherit;cursor:pointer;border-radius:8px;border:1px solid var(--trait);background:var(--champ);color:var(--encre);padding:7px 12px}
button:hover{border-color:var(--accent)}
button:focus-visible,input:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
button.principal{background:var(--accent);color:#fff;border-color:var(--accent);width:100%;margin-top:8px;padding:10px;font-weight:600}
@media (prefers-color-scheme: dark){button.principal{color:#0d1520}}
label{display:block;margin-bottom:10px;font-size:.92rem}
label span{display:flex;justify-content:space-between;color:var(--discret);font-size:.8rem}
input{width:100%;font:inherit;padding:7px 9px;border-radius:8px;border:1px solid var(--trait);background:var(--champ);color:var(--encre)}
#verdict{font-size:2rem;font-weight:700;margin:0}
#verdict.ok{color:var(--normal)} #verdict.alerte{color:var(--alerte)}
#message{color:var(--discret);margin:2px 0 16px;min-height:1.5em}
.barre{display:grid;grid-template-columns:110px 1fr 52px;gap:10px;align-items:center;margin:6px 0;font-size:.9rem}
.piste{height:12px;background:var(--champ);border:1px solid var(--trait);border-radius:6px;overflow:hidden}
.piste i{display:block;height:100%;background:var(--accent);width:0}
.piste i.top{background:var(--encre)}
.figures{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:20px}
@media (max-width:820px){.figures{grid-template-columns:1fr}}
.figures figure{margin:0;background:#fff;border-radius:8px;padding:6px;border:1px solid var(--trait)}
.figures img{width:100%;height:auto;display:block}
figcaption{color:#444;font-size:.8rem;padding:4px 6px}
.erreur{color:var(--alerte)}
</style>
</head>
<body>
<main>
  <h1>Détecteur d’intrusion réseau</h1>
  <p class="sous">Décrivez ce qu’une machine a fait pendant quelques secondes. Le modèle dit si c’est du trafic normal, un scan de ports, un déni de service ou de la force brute.</p>

  <div class="grille">
    <section aria-labelledby="t-form">
      <h2 id="t-form">Flux à analyser</h2>
      <div class="presets" id="presets"></div>
      <div id="champs"></div>
      <button class="principal" id="go" type="button">Analyser ce flux</button>
    </section>

    <div>
      <section aria-live="polite" aria-labelledby="t-res">
        <h2 id="t-res">Verdict du modèle</h2>
        <p id="verdict">Aucun flux analysé</p>
        <p id="message">Choisissez un exemple ou saisissez vos valeurs, puis analysez.</p>
        <div id="barres"></div>
      </section>

      <section style="margin-top:20px" aria-labelledby="t-eval">
        <h2 id="t-eval">Qualité du modèle sur le jeu de test</h2>
        <div class="figures">
          <figure><img src="/figures/confusion.png" alt="Matrice de confusion"><figcaption>Matrice de confusion : lignes = réalité, colonnes = prédiction.</figcaption></figure>
          <figure><img src="/figures/importance.png" alt="Importance des caractéristiques"><figcaption>Variables qui ont le plus aidé la forêt aléatoire.</figcaption></figure>
        </div>
      </section>
    </div>
  </div>
</main>

<script>
const CHAMPS = [
  ["nb_connexions","Connexions ouvertes","nombre"],
  ["nb_ports_distincts","Ports distincts visés","nombre"],
  ["paquets_par_s","Paquets par seconde","paquets/s"],
  ["taille_moy_paquet","Taille moyenne d’un paquet","octets"],
  ["taux_syn_sans_ack","Connexions jamais terminées","0 à 1"],
  ["taux_echec_auth","Échecs d’authentification","0 à 1"],
  ["duree_moy_s","Durée moyenne d’une connexion","secondes"]
];
const EXEMPLES = {
  "Navigation normale":[7,2,40,520,0.02,0.01,2.5],
  "Gros téléchargement":[2,1,4200,1410,0.01,0,40],
  "Scan de ports":[180,95,130,66,0.8,0,0.1],
  "Inondation SYN":[2600,1,6000,70,0.93,0,0.04],
  "Force brute SSH":[70,1,48,140,0.03,0.9,1.4],
  "Utilisateur distrait":[8,1,30,250,0.02,0.55,2]
};
const NOMS = {normal:"Trafic normal",scan_ports:"Scan de ports",dos:"Déni de service (DoS)",force_brute:"Force brute"};

const champs = document.getElementById("champs");
CHAMPS.forEach(([id,lib,unite])=>{
  const l = document.createElement("label");
  const s = document.createElement("span");
  s.textContent = lib; const u = document.createElement("em"); u.textContent = unite; s.appendChild(u);
  const i = document.createElement("input");
  i.type="number"; i.step="any"; i.id=id; i.min=0; i.value=0;
  l.append(s,i); champs.appendChild(l);
});

function remplir(valeurs){ CHAMPS.forEach(([id],k)=>{ document.getElementById(id).value = valeurs[k]; }); }

const presets = document.getElementById("presets");
Object.entries(EXEMPLES).forEach(([nom,v])=>{
  const b = document.createElement("button"); b.type="button"; b.textContent=nom;
  b.onclick = ()=>{ remplir(v); analyser(); };
  presets.appendChild(b);
});
remplir(EXEMPLES["Navigation normale"]);

async function analyser(){
  const corps = {};
  for (const [id] of CHAMPS){
    const v = document.getElementById(id).value;
    if (v === "") { afficherErreur("Renseignez tous les champs."); return; }
    corps[id] = Number(v);
  }
  try{
    const r = await fetch("/analyser",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(corps)});
    const d = await r.json();
    if(!r.ok){ afficherErreur(d.erreur || "Erreur inattendue."); return; }
    afficher(d);
  }catch(e){ afficherErreur("Le serveur ne répond pas. Vérifiez que dashboard.py tourne."); }
}

function afficherErreur(t){
  const v = document.getElementById("verdict");
  v.textContent = "Analyse impossible"; v.className = "alerte";
  document.getElementById("message").textContent = t;
  document.getElementById("barres").replaceChildren();
}

function afficher(d){
  const v = document.getElementById("verdict");
  v.textContent = NOMS[d.classe] || d.classe;
  v.className = d.alerte ? "alerte" : "ok";
  document.getElementById("message").textContent = d.alerte
    ? "Alerte : ce flux ressemble à une attaque. À faire vérifier par une personne avant tout blocage."
    : "Aucune alerte : ce flux ressemble à du trafic légitime.";
  const zone = document.getElementById("barres"); zone.replaceChildren();
  Object.entries(d.probabilites).sort((a,b)=>b[1]-a[1]).forEach(([c,p],k)=>{
    const ligne = document.createElement("div"); ligne.className="barre";
    const n = document.createElement("span"); n.textContent = NOMS[c] || c;
    const piste = document.createElement("div"); piste.className="piste";
    const i = document.createElement("i"); if(k===0) i.className="top"; i.style.width=(p*100)+"%"; piste.appendChild(i);
    const pc = document.createElement("span"); pc.textContent = Math.round(p*100)+" %";
    ligne.append(n,piste,pc); zone.appendChild(ligne);
  });
}
document.getElementById("go").onclick = analyser;
</script>
</body>
</html>
"""


@app.get("/")
def accueil():
    return PAGE


@app.get("/figures/<nom>")
def figure(nom):
    if nom not in ("confusion.png", "importance.png"):
        return jsonify(erreur="introuvable"), 404
    return send_from_directory(os.path.abspath("figures"), nom)


@app.post("/analyser")
def analyser():
    donnees = request.get_json(silent=True)
    if not isinstance(donnees, dict):
        return jsonify(erreur="corps JSON attendu"), 400
    ligne = {}
    for nom in CARACTERISTIQUES:
        v = donnees.get(nom)
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return jsonify(erreur=f"valeur numérique manquante ou invalide : {nom}"), 400
        bas, haut = BORNES[nom]
        if not (bas <= v <= haut):
            return jsonify(erreur=f"valeur hors plage pour {nom} (entre {bas} et {haut})"), 400
        ligne[nom] = float(v)
    probas = MODELE.predict_proba(pd.DataFrame([ligne], columns=CARACTERISTIQUES))[0]
    classe = MODELE.classes_[probas.argmax()]
    return jsonify(
        classe=str(classe),
        alerte=bool(classe != "normal"),
        probabilites={str(c): round(float(p), 3) for c, p in zip(MODELE.classes_, probas)},
    )


@app.errorhandler(500)
def erreur_interne(_):
    return jsonify(erreur="erreur interne"), 500


if __name__ == "__main__":
    print("Tableau de bord sur http://127.0.0.1:5002  (Ctrl+C pour arrêter)")
    app.run(host="127.0.0.1", port=5002)
