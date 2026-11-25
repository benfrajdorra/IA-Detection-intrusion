#!/usr/bin/env python3
"""
api.py - Met le modèle d'intrusion à disposition via une petite API HTTP (Flask), SÉCURISÉE.

POURQUOI DES PRÉCAUTIONS ? Un modèle d'IA exposé est un service comme un autre :
  - il faut AUTHENTIFIER les appelants (clé d'API) ;
  - il faut VALIDER les entrées (types, plages) : on ne donne jamais au modèle des données brutes
    venant du réseau ;
  - il faut LIMITER la taille des requêtes ;
  - on évite de divulguer des détails internes dans les erreurs ;
  - le trafic doit passer en HTTPS (certificats des projets 1 à 3).

Variables d'environnement :
  API_KEY   (obligatoire)  clé secrète attendue dans l'en-tête X-API-Key
  TLS_CERT, TLS_KEY (facultatif) : active HTTPS
  PORT      (facultatif, défaut 5001)

Usage :
  export API_KEY="$(openssl rand -hex 24)"
  python3 src/api.py
"""
import hmac
import os

import joblib
import pandas as pd
from flask import Flask, jsonify, request

paquet = joblib.load("modele/foret.joblib")
MODELE = paquet["modele"]
CARACTERISTIQUES = paquet["caracteristiques"]

# Plages plausibles pour chaque caractéristique (validation des entrées)
BORNES = {
    "nb_connexions": (0, 1_000_000),
    "nb_ports_distincts": (0, 65535),
    "paquets_par_s": (0, 10_000_000),
    "taille_moy_paquet": (0, 65535),
    "taux_syn_sans_ack": (0, 1),
    "taux_echec_auth": (0, 1),
    "duree_moy_s": (0, 86400),
}

API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise SystemExit("Erreur : définissez la variable d'environnement API_KEY avant de démarrer.")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096        # refuse les corps de requête > 4 Ko


@app.after_request
def entetes_securite(reponse):
    reponse.headers["X-Content-Type-Options"] = "nosniff"
    reponse.headers["Cache-Control"] = "no-store"
    return reponse


@app.post("/predict")
def predict():
    # 1) Authentification : comparaison en temps constant
    cle = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(cle, API_KEY):
        return jsonify(erreur="clé d'API invalide"), 401

    # 2) Validation stricte des entrées
    donnees = request.get_json(silent=True)
    if not isinstance(donnees, dict):
        return jsonify(erreur="corps JSON attendu"), 400
    ligne = {}
    for nom in CARACTERISTIQUES:
        v = donnees.get(nom)
        # bool est un sous-type de int en Python : on l'exclut explicitement
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return jsonify(erreur=f"champ numérique manquant ou invalide : {nom}"), 400
        bas, haut = BORNES[nom]
        if not (bas <= v <= haut):
            return jsonify(erreur=f"valeur hors plage pour {nom}"), 400
        ligne[nom] = float(v)

    # 3) Prédiction
    X = pd.DataFrame([ligne], columns=CARACTERISTIQUES)
    probas = MODELE.predict_proba(X)[0]
    classe = MODELE.classes_[probas.argmax()]
    return jsonify(
        classe=str(classe),
        alerte=bool(classe != "normal"),
        probabilites={str(c): round(float(p), 3) for c, p in zip(MODELE.classes_, probas)},
    )


@app.errorhandler(413)
def trop_gros(_):
    return jsonify(erreur="requête trop volumineuse"), 413


@app.errorhandler(500)
def erreur_interne(_):
    # On ne renvoie JAMAIS la trace d'erreur au client
    return jsonify(erreur="erreur interne"), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    cert, cle = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    contexte = (cert, cle) if cert and cle else None
    print(f"API sur {'https' if contexte else 'http'}://127.0.0.1:{port}  (écoute locale uniquement)")
    # host="127.0.0.1" : accessible seulement depuis la machine ; derrière Nginx pour l'exposer.
    app.run(host="127.0.0.1", port=port, ssl_context=contexte)
