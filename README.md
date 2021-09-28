######### A LIRE AVANT IMPORT ET EXECUTION #############

Ce script a été écrit vis à vis du projet 6 du parcours Admin Infra & Cloud (BAC+4) de la structure OPENCLASSROOMS

Le but de ce script étant l'audit (projet scolaire), je décline toute responsabilité en cas de détournement du code pour réaliser des actions malveillantes.

############# PREREQUIS ##################

Le script fonctionne actuellement sur debian et ubuntu -> CentOS et Redhat seront intégrés plus tard

Un serveur dns local. (bind9 dans mon cas)
Installation de john the ripper (debian) -> https://packages.debian.org/stretch/admin/john
Dictionnaire de mot de passe (petit dictionnaire 3600 mot natif à john) sinon -> google.fr  
intégration des clés SSH de l'utilisateur pour ssh sans mot de passe -> http://www.linuxproblem.org/art_9.html

######## UTILISATION ###################

python3 Audit_Linux_user.py -h affiche l'aide d'utilisation 

        -h : Affiche l'aide
        -l 'lotdemachines': Lance le script pour un groupe de machine via un fichier
        -s 'hostname' : Lance le script pour une machine
        

python3 Audit_Linux_user.py -l "chemincompletdufichierdelot"
python3 Audit_Linux_user.py -s "hostnamedelamachine"


