#!/usr/bin/env python3
"""
generer_flux.py - Fabrique un jeu de données de "fenêtres de trafic réseau" étiquetées.

Chaque ligne = ce qu'une machine source a fait pendant une fenêtre de quelques secondes,
résumé par 7 caractéristiques (features) :
  nb_connexions        nombre de connexions ouvertes
  nb_ports_distincts   nombre de ports différents visés
  paquets_par_s        débit en paquets par seconde
  taille_moy_paquet    taille moyenne d'un paquet (octets)
  taux_syn_sans_ack    part de connexions démarrées (SYN) jamais terminées
  taux_echec_auth      part de tentatives d'authentification échouées
  duree_moy_s          durée moyenne d'une connexion (secondes)

4 classes (étiquettes) :
  normal        : navigation, requêtes web, un gros téléchargement légitime ("piège")
  scan_ports    : l'attaquant sonde de nombreux ports pour trouver des services (reconnaissance)
  dos           : déni de service par inondation de SYN (des milliers de connexions ouvertes jamais terminées)
  force_brute   : essais répétés de mots de passe sur un service (ex. SSH, port 22)

Les données sont SIMULÉES (pour être réutilisables sans téléchargement). En vrai projet on utilise
des jeux publics (NSL-KDD, CIC-IDS2017, UNSW-NB15) ou ses propres captures (tcpdump / Zeek).
Les distributions se chevauchent volontairement : le problème n'est pas trivial.
Usage : python3 src/generer_flux.py   ->  data/flux.csv
"""
import os

import numpy as np
import pandas as pd

rng = np.random.default_rng(7)           # graine : résultats reproductibles
CARACTERISTIQUES = ["nb_connexions", "nb_ports_distincts", "paquets_par_s",
                    "taille_moy_paquet", "taux_syn_sans_ack", "taux_echec_auth", "duree_moy_s"]


def borne(x, bas, haut):
    return np.clip(x, bas, haut)


def normal(n):
    nav = pd.DataFrame({                  # navigation / usage courant
        "nb_connexions": rng.poisson(8, n) + 1,
        "nb_ports_distincts": rng.integers(1, 4, n),
        "paquets_par_s": rng.lognormal(3.5, 0.7, n),
        "taille_moy_paquet": borne(rng.normal(550, 250, n), 60, 1500),
        "taux_syn_sans_ack": borne(rng.beta(1, 40, n), 0, 1),
        "taux_echec_auth": borne(rng.beta(1, 50, n), 0, 1),
        "duree_moy_s": rng.exponential(3.0, n) + 0.05,
    })
    m = n // 10                           # "piège" : gros téléchargement (débit élevé mais légitime)
    dl = pd.DataFrame({
        "nb_connexions": rng.integers(1, 5, m),
        "nb_ports_distincts": rng.integers(1, 3, m),
        "paquets_par_s": rng.normal(4000, 1200, m).clip(500),
        "taille_moy_paquet": borne(rng.normal(1400, 60, m), 900, 1500),
        "taux_syn_sans_ack": borne(rng.beta(1, 60, m), 0, 1),
        "taux_echec_auth": borne(rng.beta(1, 80, m), 0, 1),
        "duree_moy_s": rng.exponential(30.0, m) + 5,
    })
    k = max(n // 20, 1)                   # "piège" : utilisateur qui se trompe plusieurs fois de mot de passe
    erreurs = pd.DataFrame({
        "nb_connexions": rng.integers(3, 20, k),
        "nb_ports_distincts": np.ones(k),
        "paquets_par_s": rng.lognormal(3.3, 0.6, k),
        "taille_moy_paquet": borne(rng.normal(250, 90, k), 60, 800),
        "taux_syn_sans_ack": borne(rng.beta(1, 40, k), 0, 1),
        "taux_echec_auth": borne(rng.uniform(0.3, 0.8, k), 0, 1),
        "duree_moy_s": rng.exponential(2.0, k) + 0.2,
    })
    j = max(n // 30, 1)                   # "piège" : outil d'inventaire/supervision légitime qui sonde des ports
    inventaire = pd.DataFrame({
        "nb_connexions": rng.normal(60, 25, j).clip(15),
        "nb_ports_distincts": rng.normal(15, 8, j).clip(5),
        "paquets_par_s": rng.normal(80, 30, j).clip(5),
        "taille_moy_paquet": borne(rng.normal(120, 50, j), 50, 400),
        "taux_syn_sans_ack": borne(rng.normal(0.35, 0.15, j), 0, 1),
        "taux_echec_auth": borne(rng.beta(1, 50, j), 0, 1),
        "duree_moy_s": rng.exponential(0.6, j) + 0.05,
    })
    return pd.concat([nav, dl, erreurs, inventaire], ignore_index=True).assign(classe="normal")


def tirage(n, nb_conn, ports, pps, taille, syn, auth, duree):
    """Fabrique n fenêtres de trafic à partir de lois (moyenne, écart-type) pour chaque variable."""
    return pd.DataFrame({
        "nb_connexions": rng.normal(*nb_conn, n).clip(1),
        "nb_ports_distincts": rng.normal(*ports, n).clip(1).round(),
        "paquets_par_s": rng.normal(*pps, n).clip(1),
        "taille_moy_paquet": borne(rng.normal(*taille, n), 40, 1500),
        "taux_syn_sans_ack": borne(rng.normal(*syn, n), 0, 1),
        "taux_echec_auth": borne(rng.normal(*auth, n), 0, 1),
        "duree_moy_s": rng.exponential(duree, n) + 0.01,
    })


def scan_ports(n):
    m = n // 4                            # 25 % de scans FURTIFS : lents et discrets, proches du normal
    agressif = tirage(n - m, (150, 60), (80, 40), (120, 60), (70, 15), (0.75, 0.12), (0.02, 0.02), 0.2)
    furtif = tirage(m, (28, 10), (12, 5), (20, 10), (75, 20), (0.50, 0.15), (0.02, 0.02), 0.4)
    return pd.concat([agressif, furtif], ignore_index=True).assign(classe="scan_ports")


def dos(n):
    m = n // 5                            # 20 % d'inondations FAIBLES : proches d'un pic de trafic légitime
    fort = tirage(n - m, (2000, 800), (1.5, 0.5), (5000, 2000), (80, 30), (0.90, 0.07), (0.01, 0.01), 0.05)
    faible = tirage(m, (450, 150), (1.5, 0.5), (1500, 500), (200, 80), (0.70, 0.12), (0.01, 0.01), 0.1)
    return pd.concat([fort, faible], ignore_index=True).assign(classe="dos")


def force_brute(n):
    m = n // 4                            # 25 % d'attaques LENTES (pour éviter le blocage de comptes)
    rapide = tirage(n - m, (60, 20), (1, 0.01), (45, 20), (150, 50), (0.04, 0.03), (0.88, 0.08), 1.5)
    lente = tirage(m, (16, 5), (1, 0.01), (20, 8), (160, 50), (0.04, 0.03), (0.60, 0.12), 2.0)
    return pd.concat([rapide, lente], ignore_index=True).assign(classe="force_brute")


if __name__ == "__main__":
    df = pd.concat([normal(1800), scan_ports(400), dos(400), force_brute(400)], ignore_index=True)
    df = df.sample(frac=1.0, random_state=7).reset_index(drop=True)
    os.makedirs("data", exist_ok=True)
    df.to_csv("data/flux.csv", index=False)
    print(f"{len(df)} fenêtres de trafic écrites dans data/flux.csv")
    print(df["classe"].value_counts())
    print("\nMoyennes par classe (arrondies) :")
    print(df.groupby("classe")[CARACTERISTIQUES].mean().round(2).T)
