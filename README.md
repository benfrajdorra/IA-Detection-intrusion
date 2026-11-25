# IA-Detection-intrusion
Machine Learning-based Network Intrusion Detection System using Random Forest, Flask REST API, and a web dashboard to detect and classify suspicious network traffic (DoS, Port Scanning, Brute Force).
 # AI-Based Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Random%20Forest-green)
![Flask](https://img.shields.io/badge/API-Flask-black)
![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red)

## Project Overview

This project aims to develop a Machine Learning-based Network Intrusion Detection System (IDS).

It uses the **Random Forest algorithm** to analyze network traffic features, detect suspicious activities, and classify different types of cyberattacks.

The system includes a **Flask REST API** secured with an API key, as well as a web dashboard that allows users to test the intrusion detection model and visualize prediction results.

The main goal is to explore the application of Machine Learning in cybersecurity and build an intelligent prototype for network intrusion detection.

## Features

- Network traffic dataset generation.
- Machine Learning model training and evaluation.
- Random Forest classification.
- Detection of suspicious network activities.
- Flask REST API protected with an API key.
- Input validation and error handling.
- Optional HTTPS communication.
- Web dashboard for testing predictions.
- Confusion matrix visualization.
- Feature importance visualization.

## Attack Types Detected

The system classifies network traffic into four categories:

| Class | Description |
|---|---|
| Normal | Legitimate network traffic |
| Port Scanning | Attempts to discover open network ports |
| DoS | Denial of Service attacks |
| Brute Force | Repeated authentication attempts |

## Technologies Used

- **Python** – Main programming language.
- **Scikit-learn** – Machine Learning algorithms.
- **Pandas** – Dataset processing.
- **Flask** – REST API and web dashboard.
- **Joblib** – Model serialization and loading.
- **HTML / CSS** – Dashboard interface.
- **OpenSSL** – TLS certificate generation.

## Dataset

The project uses a simulated network traffic dataset generated with Python.

It contains seven network traffic features:

1. `nb_connexions`
2. `nb_ports_distincts`
3. `paquets_par_s`
4. `taille_moy_paquet`
5. `taux_syn_sans_ack`
6. `taux_echec_auth`
7. `duree_moy_s`

The dataset contains four traffic categories: Normal, Port Scanning, DoS, and Brute Force.

## Project Structure

```text
IA-Detection-intrusion/
│
├── src/
│   ├── api.py
│   ├── dashboard.py
│   ├── entrainer.py
│   ├── generer_flux.py
│   ├── gen_certs.py
│   └── client_test.py
│
├── data/
│   └── flux.csv
│
├── modele/
│   └── foret.joblib
│
├── figures/
│   ├── confusion.png
│   └── importance.png