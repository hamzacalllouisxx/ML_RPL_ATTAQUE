Introduction
Ce projet est une application web Streamlit pour l'analyse des fichiers CSV et la comparaison des performances des algorithmes K-Nearest Neighbors (KNN) et Random Forest dans la détection des attaques dans les environnements IoT. L'application traite les fichiers CSV pour extraire des fonctionnalités, visualise les données et effectue des classifications en utilisant les algorithmes KNN et Random Forest. Les résultats sont affichés avec diverses visualisations pour aider à comprendre les données et les performances des modèles.

Prérequis
Avant d'exécuter l'application, assurez-vous d'avoir les éléments suivants installés :

Python 3.7 ou supérieur
Streamlit
Pandas
Numpy
Scikit-learn
Matplotlib
Seaborn

Étape 1: Données brutes
Les données brutes utilisées pour l'entraînement du modèle ont été obtenues selon les étapes suivantes :

Installer le simulateur IoT Contiki Cooja sur un ordinateur avec le système d'exploitation Ubuntu 18.04.
Simuler des dispositifs IoT en utilisant Contiki Cooja, en créant à la fois des nœuds vulnérables et normaux.
Capturer les données brutes pendant les simulations et les convertir au format de fichier CSV.
6 ensembles de données différents ont été créés à partir des simulations utilisant Contiki Cooja.

Étape 2: Exécuter l'Application
Vous pouvez installer les bibliothèques requises en utilisant pip :
pip install streamlit pandas numpy scikit-learn matplotlib seaborn

Cloner le Répertoire

Clonez ce répertoire sur votre machine locale en utilisant la commande suivante :
git clone <repository_url>

Accédez au répertoire du projet :
cd ML_RPL_ATTAQUE

Exécuter l'Application Streamlit

Démarrez l'application Streamlit en exécutant :
streamlit run app.py


Télécharger les Fichiers CSV

Étape 1 : Ouvrez votre navigateur web et accédez à l'URL fournie par Streamlit (typiquement http://localhost:8501).
Étape 2 : Téléchargez un fichier de simulation normal (format CSV) en cliquant sur le bouton "Uploader un fichier de simulation normal".
Étape 3 : Téléchargez un fichier de simulation d'attaque (format CSV) en cliquant sur le bouton "Uploader un fichier de simulation contient des attaques".
Sélectionner les Options de Visualisation

Étape 4 : Dans la barre latérale, sélectionnez l'option de visualisation que vous souhaitez utiliser parmi "Random Forest", "KNN" ou "Comparison".
Traiter les Fichiers

Étape 5 : Cliquez sur le bouton "Process Files" pour commencer à traiter les fichiers téléchargés. L'application traitera les fichiers CSV, extraira les fonctionnalités et affichera les données traitées.
Voir les Résultats

Étape 6 : Visualisez les données traitées, les visualisations et les résultats de comparaison des modèles affichés sur la page principale.


