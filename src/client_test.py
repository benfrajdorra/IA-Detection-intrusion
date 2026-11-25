#!/usr/bin/env python3
"""
client_test.py - Envoie des exemples de trafic à l'API et affiche les verdicts.
Usage :  API_KEY=... python3 src/client_test.py [url] [ca.crt]
"""
import os
import sys

import requests

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5001/predict"
CA = sys.argv[2] if len(sys.argv) > 2 else True       # True = CA du système ; sinon chemin de notre CA
CLE = os.environ.get("API_KEY", "")

EXEMPLES = {
    "navigation normale": dict(nb_connexions=7, nb_ports_distincts=2, paquets_par_s=40, taille_moy_paquet=520,
                               taux_syn_sans_ack=0.02, taux_echec_auth=0.01, duree_moy_s=2.5),
    "gros téléchargement": dict(nb_connexions=2, nb_ports_distincts=1, paquets_par_s=4200, taille_moy_paquet=1410,
                                taux_syn_sans_ack=0.01, taux_echec_auth=0.0, duree_moy_s=40),
    "scan de ports": dict(nb_connexions=180, nb_ports_distincts=95, paquets_par_s=130, taille_moy_paquet=66,
                          taux_syn_sans_ack=0.8, taux_echec_auth=0.0, duree_moy_s=0.1),
    "inondation SYN (DoS)": dict(nb_connexions=2600, nb_ports_distincts=1, paquets_par_s=6000, taille_moy_paquet=70,
                                 taux_syn_sans_ack=0.93, taux_echec_auth=0.0, duree_moy_s=0.04),
    "force brute SSH": dict(nb_connexions=70, nb_ports_distincts=1, paquets_par_s=48, taille_moy_paquet=140,
                            taux_syn_sans_ack=0.03, taux_echec_auth=0.9, duree_moy_s=1.4),
}

for nom, ex in EXEMPLES.items():
    r = requests.post(URL, json=ex, headers={"X-API-Key": CLE}, verify=CA, timeout=5)
    print(f"{nom:24s} -> {r.status_code} {r.json()}")

print("\n--- Tests de rejet ---")
print("Sans clé        :", requests.post(URL, json=EXEMPLES["scan de ports"], verify=CA, timeout=5).status_code)
mauvais = dict(EXEMPLES["scan de ports"], taux_syn_sans_ack=7)
print("Valeur hors plage:", requests.post(URL, json=mauvais, headers={"X-API-Key": CLE}, verify=CA, timeout=5).status_code)
print("Champ manquant  :", requests.post(URL, json={"nb_connexions": 3}, headers={"X-API-Key": CLE}, verify=CA, timeout=5).status_code)
