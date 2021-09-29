######### A LIRE AVANT IMPORT ET EXECUTION #############

        Ce script a été écrit vis à vis du projet 6 du parcours Admin Infra & Cloud (BAC+4) de la structure OPENCLASSROOMS

        Le but de ce script étant l'audit (projet scolaire), je décline toute responsabilité en cas de détournement du code pour réaliser des actions malveillantes.

############# PREREQUIS ##################

        Le script fonctionne actuellement sur debian et ubuntu -> CentOS et Redhat seront intégrés plus tard

        Un serveur dns local. (bind9 dans mon cas)
        Installation de john the ripper (debian) -> https://packages.debian.org/stretch/admin/john
        Dictionnaire de mot de passe (petit dictionnaire 3600 mot natif à john) sinon -> google.fr  
        intégration des clés SSH de l'utilisateur pour ssh sans mot de passe -> http://www.linuxproblem.org/art_9.html
        Création des dossiers /expl/scripts et /expl/logs

        
######## UTILISATION ###################

        python3 Audit_Linux_user.py -h affiche l'aide d'utilisation 

        -h : Affiche l'aide
        -l 'lotdemachines': Lance le script pour un groupe de machine via un fichier
        -s 'hostname' : Lance le script pour une machine
        

        python3 Audit_Linux_user.py -l "chemincompletdufichierdelot"
        python3 Audit_Linux_user.py -s "hostnamedelamachine"
        
       
       Séquençage du script : 
                Création d"un dossier avec le timestamp actuelle (Audit_AAAAMMJJHHMM) dans /expl/logs pour accueillir le logger
                Init du logger
                Obtention des crédentials de l'utilisateur exécutant le script (admaic)
                Test ping hostname ou IP si hostname échoue
                Récupération des informations machines (OS,Kernel)
                Vérifie si la machine est à jour via le site officiel -> regex
                Récupération des utilisateurs de la machine en se basant sur le /home dans /etc/passwd
                Analyse de l'history des users et regarde si des commandes "dangereuses" ont été lancés
                Audit password ? 
                        si oui : renseignement mot de passe
                                vérification concordance password
                                Mode d'audit (Rapide ou Lent ) 
                                Utilisation John pour déchiffrer mot de passe
                                Analyse compléxité password
                                si password faible : 
                                        Envoie mail à user
                                Fermeture logger
                                envoie mail IT
                        si non  :
                                Fin du script
                                Fermeture logger
                                Envoie mail à l'IT


