#!/usr/bin/env python3
"""
entrainer.py - Entraîne un détecteur d'intrusion RÉSEAU (classification supervisée).

CONCEPT : apprentissage SUPERVISÉ
  Ici, on dispose d'exemples ÉTIQUETÉS (normal, scan_ports, dos, force_brute). Le modèle apprend à
  reconnaître chaque famille d'attaque et peut dire LAQUELLE il voit (contrairement au projet 9).
  Limite : il ne connaît que les attaques vues à l'entraînement.

CONCEPT : arbre de décision vs forêt aléatoire
  - Arbre de décision : suite de questions "si x > seuil alors ..." ; très EXPLICABLE (on peut le lire).
  - Forêt aléatoire (Random Forest) : plusieurs centaines d'arbres entraînés sur des échantillons
    différents qui VOTENT ; plus robuste et plus précise, moins lisible.
  On compare les deux.

CONCEPT : validation croisée
  On découpe les données en 5 parts ; on entraîne sur 4, on teste sur la 5e, et on recommence 5 fois.
  Donne une estimation plus FIABLE qu'un seul découpage.

CONCEPT : importance des caractéristiques
  Mesure quelles variables ont le plus aidé le modèle : utile pour comprendre et pour décider quoi
  capturer sur le réseau.
Usage : python3 src/entrainer.py
"""
import os

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import ConfusionMatrixDisplay, classification_report
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text

CARACTERISTIQUES = ["nb_connexions", "nb_ports_distincts", "paquets_par_s",
                    "taille_moy_paquet", "taux_syn_sans_ack", "taux_echec_auth", "duree_moy_s"]

df = pd.read_csv("data/flux.csv")
X, y = df[CARACTERISTIQUES], df["classe"]
X_app, X_test, y_app, y_test = train_test_split(X, y, test_size=0.25, random_state=7, stratify=y)

# --- Modèle 1 : arbre de décision peu profond (explicable) --------------------
arbre = DecisionTreeClassifier(max_depth=4, random_state=7).fit(X_app, y_app)
# --- Modèle 2 : forêt aléatoire ------------------------------------------------
# class_weight="balanced" : compense le fait qu'il y a plus de trafic normal que d'attaques
foret = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=7, n_jobs=-1)
foret.fit(X_app, y_app)

print("=== Validation croisée (5 plis) sur l'apprentissage ===")
for nom, m in [("Arbre (profondeur 4)", arbre), ("Forêt aléatoire", foret)]:
    scores = cross_val_score(m, X_app, y_app, cv=5, scoring="f1_macro")
    print(f"{nom:22s} F1 moyen = {scores.mean():.3f}  (± {scores.std():.3f})")

print("\n=== Évaluation finale de la forêt sur le jeu de TEST (jamais vu) ===")
y_pred = foret.predict(X_test)
print(classification_report(y_test, y_pred, digits=3))

print("=== Règles apprises par l'arbre (lisibles par un humain) ===")
print(export_text(arbre, feature_names=CARACTERISTIQUES, max_depth=4))

# --- Sauvegardes -----------------------------------------------------------------
os.makedirs("modele", exist_ok=True)
joblib.dump({"modele": foret, "caracteristiques": CARACTERISTIQUES}, "modele/foret.joblib")
print("Modèle sauvegardé : modele/foret.joblib")

os.makedirs("figures", exist_ok=True)
fig, ax = plt.subplots(figsize=(6.5, 5.5))
ConfusionMatrixDisplay.from_predictions(y_test, y_pred, ax=ax, cmap="Blues", xticks_rotation=30)
ax.set_title("Matrice de confusion (jeu de test)")
fig.tight_layout()
fig.savefig("figures/confusion.png", dpi=110)

importances = pd.Series(foret.feature_importances_, index=CARACTERISTIQUES).sort_values()
fig, ax = plt.subplots(figsize=(7, 4))
importances.plot.barh(ax=ax, color="#457b9d")
ax.set_title("Importance des caractéristiques (forêt aléatoire)")
fig.tight_layout()
fig.savefig("figures/importance.png", dpi=110)
print("Figures : figures/confusion.png et figures/importance.png")
