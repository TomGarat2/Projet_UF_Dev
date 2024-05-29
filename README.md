# Projet de Crypteur/Décrypteur de Fichiers

## Description
HackEncrypt est une application web dédiée à la sécurisation de vos fichiers à travers un processus de cryptage et décryptage efficace et facile à utiliser. Cette plateforme permet aux utilisateurs de protéger leurs données sensibles avec des technologies de chiffrement avancées.

## Fonctionnalités
- **Inscription et connexion des utilisateurs**
- **Cryptage et décryptage de fichiers**
- **Gestion des fichiers cryptés et décryptés**
- **Historique des clés de cryptage utilisées**
- **Réinitialisation de mot de passe via email**
- **Gestion des rôles d'utilisateurs (Admin et Utilisateur régulier)**
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
- HTML/CSS/JavaScript

## Pourquoi ces technologies ?

- Python : Choisi pour sa simplicité, sa lisibilité et son large écosystème de bibliothèques qui facilitent le développement rapide d'applications robustes.

- Flask : Un micro-framework léger et flexible qui permet une grande liberté dans la conception de l'application. Idéal pour des projets de taille moyenne où l'on souhaite éviter la complexité des frameworks plus lourds.

- SQLAlchemy : Une ORM puissante pour Python qui simplifie l'interaction avec la base de données et permet une gestion propre et structurée des données.

- Flask-Login : Pour la gestion de l'authentification des utilisateurs, offrant des fonctionnalités essentielles comme la gestion des sessions utilisateur.

- Flask-WTF : Pour la gestion et la validation des formulaires web, simplifiant le traitement des entrées utilisateur.
pycryptodome : Bibliothèque de cryptographie moderne et complète, permettant de mettre en œuvre des algorithmes de cryptage robustes comme AES.

- HTML/CSS/JavaScript : Pour créer une interface utilisateur attrayante et interactive, en utilisant des technologies web standards.

- Flask-Mail : Pour l'envoi d'emails, notamment pour les fonctionnalités de réinitialisation de mot de passe.


## Prérequis
- Python 3.x
- Git

## Installation

### Cloner le Répertoire du Projet
```sh
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

Gestion des Rôles d'Utilisateurs:
Pour promouvoir un utilisateur en administrateur, utilisez le script make_admin.py :
python make_admin.py <username>

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