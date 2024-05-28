# Projet de Crypteur/Décrypteur de Fichiers - HackEncrypt

## Description
HackEncrypt est une application web qui permet de crypter et décrypter des fichiers afin de protéger des données sensibles. L'application utilise Python et Flask, accompagnés de diverses bibliothèques de cryptographie. Les utilisateurs peuvent s'inscrire, se connecter, gérer leurs fichiers et visualiser l'historique des clés de cryptage utilisées. L'application comprend également des fonctionnalités avancées de gestion des utilisateurs et de sécurité.

## Fonctionnalités
- **Inscription et connexion des utilisateurs**
- **Cryptage et décryptage de fichiers**
- **Gestion des fichiers cryptés et décryptés**
- **Historique des clés de cryptage utilisées**
- **Réinitialisation de mot de passe via e-mail sécurisé**
- **Rôles d'utilisateurs (admin, utilisateur régulier)**
- **Interface utilisateur intuitive et sécurisée**

## Technologies Utilisées
- Python
- Flask
- SQLAlchemy
- Flask-Login
- Flask-WTF
- pycryptodome
- Flask-Mail
- Flask-Talisman
- Flask-Limiter
- pyotp
- HTML/CSS/JavaScript

## Prérequis
- Python 3.x
- Git

## Installation

### Cloner le Répertoire du Projet
```bash
git clone <URL_DE_VOTRE_DEPOT>
cd <NOM_DU_REPERTOIRE_DU_PROJET>

Créer un Environnement Virtuel

Sur macOS :
python3 -m venv env
source env/bin/activate

Sur Windows :
python -m venv env
.\env\Scripts\activate

Installer les Dépendances :
pip install -r requirements.txt

Démarrage de l'Application

Sur macOS et Windows :
python app.py


Utilisation :
Ouvrez votre navigateur et accédez à http://127.0.0.1:5000
Inscrivez-vous ou connectez-vous
Utilisez l'interface pour crypter ou décrypter vos fichiers
Consultez l'historique des clés de cryptage utilisées
Résolution des Problèmes Courants
Dépendances Manquantes ou Versions Incorrectes
Vérifiez le fichier requirements.txt et réinstallez les dépendances :
pip install -r requirements.txt

Problèmes de Base de Données
Supprimez l'ancienne base de données (si nécessaire) et recréez-la :

Sur macOS :
pip install -r requirements.txt

Sur Windows :
del instance\site.db

Puis recréez la base de données :
python
>>> from app import db
>>> db.create_all()
>>> exit()

Activation de l'Environnement Virtuel
Assurez-vous d'avoir activé l'environnement virtuel avant d'installer les dépendances ou de lancer l'application.

Auteur
Tom Garat