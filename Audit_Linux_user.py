#!/bin/python3

print("""
   Project : Audit_Linux_User
   @type : Audit_Linux_user.py
   @note : OPENCLASSROOMS AIC P6 (DEBIAN/UBUNTU)
   @author = Quentin GAUTIER
   @version = 1.0
   @copyright = Quentin GAUTIER
   @git = https://github.com/QGAUTIER3/AIC
""")
############################## IMPORT ##########################
import os # Action de l'OS
import sys # Gestion des args
import time #timestamp
import logging # Logger
from logging.handlers import RotatingFileHandler    # Rotatefile #
import requests # Requete web
import re #Regex Python#
import subprocess # run command
import getpass # Gestion crédentials
import base64 as b #Secret
import crypt # secret
from email.message import EmailMessage # mail
import ssl # mail 
import smtplib # mail 
###############################################################

########################## VARIABLES STATIQUES ###############
user_script = "admaic"
log_path = "/expl/logs/"
temps = (time.strftime("%Y%m%d%H%M"))
header = "__" + temps + "__"
inventaire = "/expl/scripts/inventaire_parc.csv"
regex_debian = re.compile("linux-image-[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}-[0-9]{1,2}-amd64")
regex_ubuntu = re.compile("linux-image-[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}-[0-9]{1,2}-generic")
rssi = "bW90ZGVwYXNzZQ=="
dict_path = "/home/admaic/dict_pass/"
small_dictionnaire = "password.lst"
large_dictionnaire = "rockyou.txt"

##############################################################

########################### FUNCTIONS ########################
def logactivityinit(file):
    """
    Initialize the logger"
    """
    # création de l'objet logger qui va nous servir à écrire dans les logs
    logger = logging.getLogger()
    # on met le niveau du logger à DEBUG, comme ça il écrit tout
    logger.setLevel(logging.DEBUG)
    if logger.hasHandlers(): 
        logger.handlers = []
    # création d'un formateur qui va ajouter le temps, le niveau
    # de chaque message quand on écrira un message dans le log
    formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
    # création d'un handler qui va rediriger une écriture du log vers
    # un fichier en mode 'append', avec 1 backup et une taille max de 10Mo
    file_handler = RotatingFileHandler(file, 'a', 10000000, 1)
    # on lui met le niveau sur DEBUG, on lui dit qu'il doit utiliser le formateur
    # créé précédement et on ajoute ce handler au logger
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.propagate = False
    # création d'un second handler qui va rediriger chaque écriture de log
    # sur la console
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    logger.addHandler(stream_handler)
    return logger , file_handler

def logactivityclose(file_handler, logactivity, log_path, logger):
    """
    close the logger
    """
    file_handler.flush()
    file_handler.close()
    logger.removeHandler(file_handler)
    logging.shutdown()

def usage():
    """Affiche comment utiliser le script"""
    print("""
        -h : Affiche l'aide
        -l 'lotdemachines': Lance le script pour un groupe de machine via un fichier
        -s 'hostname' : Lance le script pour une machine
        """)

def create_directory_logs(log_path,timestamp, nom_dossier):
    """ Créer un nouveau dossier avec l'horodatage
    """
    if not os.path.exists(log_path+timestamp+nom_dossier): # Si le dossier n'existe pas on le crée
        try:
            os.chdir(log_path)
            os.mkdir(nom_dossier+"{}".format(timestamp))
        except:
            print("Erreur au niveau de la création du dossier")
    log_path = log_path + nom_dossier + timestamp # Return le nouveau log_path
    print("""Les logs de cette execution de script iront dans :
    {}""".format(log_path))
    return log_path

def is_online(hostname):
    """
    Teste si une machine est online par nom ou IP
    """
    ping_nom = os.system("ping -c 1 {} >> /dev/null 2>&1 ".format(hostname)) # ping silencieux
    if ping_nom != 0:
        logger.warning("Ping Hostname KO")
        logger.info("Ping IP en cours")
        
        with open(inventaire) as f: # Si le ping hostname n'a pas marché on cherche dans un fichier csv son ip format ("hostname;ip")
            lines = f.readlines()
            for line in lines:
                if hostname in line.split(";")[0]:
                    ip = line.split(";")[1]
    
        ping_ip = os.system("ping -c 1 %s  >> /dev/null 2>&1 " % (ip)) # ping de son ip 
        if ping_ip == 0:
            logger.info("Ping %s OK" % (ip))
            return ip    
        else:
            logger.critical("""Ping Hostname %s KO & Ping IP %s KO""" %(hostname,ip))         
    else:
        logger.info("Ping {} OK".format(remote_hostname))
        return remote_hostname

def create_result():
    """
    Creation fichier de résultat format xls 
    #TODO HORS AIC
    """
    #df = pandas.DataFrame

def get_os_version(remote_hostname):
    """
    Obtiens l'OS/Version/kernel d'une machine distante
    """
    # Création d'un dictionnaire pour tout stocker
    infos = dict()
    command_os = "hostnamectl | grep Operating | awk -F ':' '{print $2}'" #Stock des cmd bash sous string pour clarté du code
    command_kernel = "hostnamectl | grep Kernel | awk -F ':' '{print $2}' | awk -F ' ' '{print $2}'" # idem
    logger.info("Récupération Infos venant de %s" % (remote_hostname))

    try:
        os_distant = subprocess.check_output(["ssh",remote_hostname, command_os])
        os_kernel = subprocess.check_output(["ssh",remote_hostname, command_kernel])
        
    except:
        logger.warning("La machine ne dispose pas d'hostnamectl #TODO hors projet AIC/ ")

    # Mise en forme
    os_distant = str(os_distant).replace("b'", "").replace("\\n'", "")
    os_kernel = str(os_kernel).replace("b'", "").replace("\\n'", "")

    infos = {
        "hostname": remote_hostname,
        "OS": os_distant,
        "Kernel": os_kernel
        }
    
    logger.info("OS de la machine : %s" %(os_distant))
    logger.info("Kernel de la machine : %s" %(os_kernel))
    return infos
        


def get_last_patch(infos_machine):
    """
    Check si la machine a le dernier noyau linux depuis le site en fonction de son OS et compare des deux
    """
    
    debian_11 = {
        "OS": " Debian GNU/Linux 11 (bullseye)",
        "url": "https://packages.debian.org/bullseye/linux-image-amd64"
        
    }

    ubuntu_20 = {
        "OS": " Ubuntu 20.04.3 LTS",
        "url": "https://packages.ubuntu.com/focal/kernel/"
    }

    if infos_machine["OS"] == debian_11["OS"]:
        logger.info("Récupération du dernier kernel pour : {}".format(infos_machine["OS"]))
        
        # Request Web
        req = requests.get(debian_11["url"])
        if req.status_code == 200:
            logger.info("Requete Web OK")
        else:
            logger.warning("Requete Web NOK")
               
        try:
            reg = re.search(regex_debian, str(req.text)) #Regex pour isoler le kernel
        except:
            logger.warning("Pas de kernel dans cette page")  
        if reg: # Si la regex choppe un item
            version = reg.group(0)
            version = version.split("-")
            version = version[2] + "-"+version[3]+"-"+version[4]
            logger.info("Compare des deux kernel en cours")
        
        if infos_machine["Kernel"] == version:
            logger.info("La machine est à jour")
        else:
            logger.warning("La machine n'est pas à jour")

    elif infos_machine["OS"] == ubuntu_20["OS"]:
        
        logger.info("Récupération du dernier kernel pour : {}".format(infos_machine["OS"]))
        req = requests.get(ubuntu_20["url"]) #request web
        
        if req.status_code == 200:
            logger.info("Requete Web OK")
        else:
            logger.warning("Requete Web NOK")
        try:
            reg = re.findall(regex_ubuntu, str(req.text)) #Regex pour isoler les kernels (beaucoup de kernel)
            #Itération sur les kernels pour isoler le dernier kernel
            for ref in reg:
                if ref[12] >= infos_machine['Kernel'][0]:
                    if ref[14:16] >= infos_machine['Kernel'][2:4]:
                        if ref[17] >= infos_machine['Kernel'][5]:
                            if ref[19:21] >= infos_machine['Kernel'][7:9]:
                                result = ref
                                
                                  
        except:
            logger.warning("Pas de kernel dans cette page")  
        

        if result:
            print(result)
            version = result.split("-")
            version = version[2] + "-"+version[3]+"-"+version[4]
            print(version)
            logger.info("Compare des deux kernel en cours")
        
        if infos_machine["Kernel"] == version:
            logger.info("La machine est à jour")
        else:
            logger.warning("La machine n'est pas à jour")


def get_users(remote_hostname):
    """
    Retourne une liste d'utilisateurs présent sur le serveur à des fin d'analyse history/password
    """
    distant = "%s@%s" % (user_script,remote_hostname) # admaic@$computer
    command_users = "grep home /etc/passwd | awk -F ':' '{print $1}'" # command bash en string pour clarté code
    logger.info("Récupération Users sur : %s" % (remote_hostname))
    users_distant = ()
    try:
        users_distant = subprocess.check_output(["ssh" , "%s" % distant, command_users])
        users_distant = str(users_distant).replace("b'","").replace("\\n'","").split("\\n") # mise en forme
    except:
        logger.warning("La commande à échoué ")
    return users_distant

def get_history(remote_hostname, users):
    """
    Va checker les .history voir si des commandes dangereuses ont été lancés
    """
    logger.info("Début de l'analyse de l'history user")

    distant = "%s@%s" % (user_script,remote_hostname)
    command_warning = ["sudo","remove","upgrade","rm","rmdir","apt", "*.sh"] # liste commande "dangereuse"
    logger.info("Les commandes dangereuses sont : {}".format(command_warning))
    for user in users: # Itération sur les users
        if user == user_script or user == "syslog" or user == "cups-pk-helper": # Exclusion parceque admaic = presque root et autre car le grep les recupere#
            logger.info("Exclusion de l'analyse pour {}".format(user))
        else:
            logger.info("Analyse History pour l'utilisateur {} sur {}".format(user,remote_hostname))
            command_history = "echo -e %s | sudo -S cat /home/%s/.bash_history" % (user_script_pass,user) # Stock cmd bash pour clarté code
            try:
                history = subprocess.check_output(["ssh",distant,command_history]) # recup history
                history = str(history).replace("b'","") # mise en forme
                history = str(history).split("\\n") # mise en forme
                for hist in history: # itération de chaque ligne history
                    for cmd  in command_warning: # itération de chaque cmd dangereuse
                        if cmd in hist:
                            logger.warning("commande dangereuse {} pour {} sur : {}".format(cmd,user,remote_hostname))
                    
                    
            except:
                logger.warning("Erreur dans la récupération de l'history pour {} sur : {}".format(user,remote_hostname))

def get_shadow(remote_hostname,users):
    """
    Récupere le /etc/shadow des users et l'envoi dans une variable
    """
    command_shadow = "echo -e %s | sudo -S cat /etc/shadow | egrep " % (user_script_pass) # egrep (pour "regex")sur le /etc/shadow
    distant = "%s@%s" % (user_script,remote_hostname)
    logger.info("Début l'analyse de compléxité des mot de passe")
    for user in users:
        if user == user_script or user == "syslog" or user == "cups-pk-helper": # always exclusion
            logger.info("Exclusion de l'utilisateur %s pour analyse password" % (user))    
        else:
               command_shadow = command_shadow + "%s\|" % (user) # on ajoute au egrep les users  exemple "julie\|alice\|" pour OU logique
    
    command_shadow = command_shadow[0:-2] # Exclusion des 2 derniers caractères car "\|" -> fausse le egrep
    try:
        shadow = subprocess.check_output(["ssh",distant,command_shadow]) # Sors une list des users format shadow $user:$algochiffr$$key
        shadow = str(shadow).replace("b'","") # mise en forme
        shadow = str(shadow).split("\\n") # mise en forme
    except:
        logger.warning("Erreur dans la récupération /etc/shadow sur %s" % (remote_hostname))
    if shadow:
        logger.info("Récupération shadow OK")
    return shadow

def temp_pass(shadow,remote_hostname):
    """
    Crée un fichier temporaire contenant la liste format shadow dans le dossier de logs
    """
    shadow_file = remote_hostname + "_pass.txt" # Generation du fichier
    if not os.path.exists(log_path2+shadow_file): # si le fichier n'existe pas déjà
        try:
            with open(log_path2+"/"+remote_hostname+"_pass.txt","w") as f: # on l'ouvre
                for user in shadow:
                    f.write(user) 
                    f.write("\n")
        except:
                logger.critical("Erreur au niveau de la création du fichier")
    logger.info("Création fichier temporaire OK pour stocker le /etc/shadow")
    return shadow_file

def jtr(vitesse,shadow_file):
    """
    Prends en entrée le fichier temporaire /etc/shadow et analyse les password des users
    Information : Jtr = John the reaper
    """
    regex_john = re.compile(".{2,10}:") #Exclusion lignes inutiles
    result_list = []
    full_path = log_path2+"/"+shadow_file
    if vitesse == "R":
        logger.info("Utilisation dictionnaire {}".format(small_dictionnaire))
        command_wordlist = "--wordlist="+dict_path + small_dictionnaire
        
        try:
            os.system("john %s %s >> /dev/null 2>&1" % (command_wordlist,full_path)) #attaque de type dictionnaire rapide (3600 mots)
        except:
            logger.critical("Erreur dans l'éxécution de john")

    elif vitesse == "L":
        logger.info("Utilisation dictionnaire {}".format(large_dictionnaire))
        command_wordlist = "--wordlist="+dict_path + large_dictionnaire
        try:
            os.system("john %s %s >>/dev/null 2>&1" % (command_wordlist,full_path)) # attaque de type dictionnaire lent (14Million de mots)
        except:
            logger.critical("Erreur dans l'éxécution de john")

    #TODO : "X" = john intensif # HORS AIC
    cracked = subprocess.check_output("john --show %s " % (full_path),shell=True) # voir si john à réussi
    cracked = cracked.decode('utf-8')

    if cracked != "0 password hashes cracked, 0 left\n": # si john a réussi
        logger.info("Déchiffrement mot de passe OK")
        logger.info("Constitution d'une liste en cours")
        cracked = str(cracked).split("\n") # mise en forme
        for user_cracked in cracked:
            reg = re.search(regex_john, str(user_cracked)) # regex pour isoler ("user:motdepasse")
            if reg:
                result_list.append(user_cracked) # ajout dans une liste
        return result_list            
    else:
        logger.warning("Déchiffrement des mot de passe KO")
        return False # john n'a pas réussi ( exemple : type yescrypt ou pass pas dans dictionnaire)
        
def password_is_weak(liste):
    """
    Va analyser les password sur critères suivant : (longueur > 8, Majuscules 2minimum, CaracSpécial 1 minimum)
    """
    
    for line in liste: # parcours de la liste fourni par jtr juste au dessus
        count_maj = 0
        special_characters = '"!@#$%^&*()-+?_=,<>/"'
        count_special = 0 
        line_user = str(line).split(":")[0] # extract user
        line_user_pass = str(line).split(":")[1] # extract pass
        logger.info("Analyse Pass pour : %s " % (line_user))
        for carac in line_user_pass: # itération caractere password
            if carac.isupper(): # si c'est une majuscule
                count_maj = count_maj + 1
            for c in special_characters:                
                if carac == c: # si c'est un caractère special
                    count_special = count_special + 1 
        if len(line_user_pass) >= 8 and count_maj >= 2 and  count_special >= 1: # critères mdp
            continue # ok passe à la prochaine itération
        else:
            logger.warning("Mot de passe faible pour : %s" % (line_user))
            SendMailUser(line_user)

def SendMailUser(blameuser):
    """
    Envoie un mail aux users si le mot de passe est faible
    """
    distant = "%s@%s" % (user_script,remote_hostname)
    command_mail = "echo 'Votre mot de passe sur la machine %s est faible. Merci de le changer' | mail -s '[Audit Mot de passe]' %s " % (remote_hostname,blameuser)
    try:
        subprocess.check_output(["ssh",distant,command_mail]) # on ssh la machine distant puis mail(natif) à l'utilisateur 
        logger.info("Mail envoyé à l'utilisateur %s " % (blameuser))
    except:
        logger.warning("Echec de l'envoi du mail à %s " % (blameuser))

def SendMailIT(logfile):
    """
    Envoie une copie du logger à moi même via gmail juste histoire de :)
    """
    subject = "[AUDIT ACTIVITY]"
    body = (" Bonjour, \n\nVous trouverez dans ce mail le logger d'audit \n"
    "\n" 
    "Chemin des logs du script %s" % (log_path2))
    receiver_email = "quentin.gautier33@gmail.com" # TODO enlever mon mail perso ou l'obfuscer
    sender_email = "aic.ssi.p6@gmail.com" # crée pour le projet
    
    msg = EmailMessage()
    msg["From"] = sender_email
    msg["Subject"] = subject
    msg["To"] = receiver_email
    msg.set_content(body)
    msg.add_attachment(open(log_file, "r").read(), filename=log_file) # ajout du logger en pièce-jointe
    password_mail = getpass.getpass("Saisir password mail IT : ") # mot de passe du compte sender_email (hide pass from console)
    try:
        s = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        s.login(sender_email, password_mail)
        s.send_message(msg)
        print("Envoie du mail OK")
    except:
        print("Envoie du mail NOK")
################## MAIN ################################################

# Check des arguments fournis 
try:
    if not sys.argv[1]: # si pas d'arguments
        usage()
        exit()
except IndexError:
        print("Aucun argument n'a été fournit")
        exit()

if sys.argv[1] == "-h": # si le premier argument est "-h"
    usage()
    exit()
elif sys.argv[1] != "-l" and sys.argv[1] != "-s": # si le premier arg n'est pas -s ou -l 
    print("Argument Invalide {}".format(sys.argv[1]))
    usage()
    exit()
elif sys.argv[1] and len(sys.argv) != 3: # si il n'y pas de troisième arg
    print("Le script requiert un argument supplémentaire pour l'option {}".format(sys.argv[1]))
    exit()

# Create dossier pour accueillir les logs de cette instance d'éxécution
log_path2 = create_directory_logs(log_path,temps,"Audit_User_")
os.chdir(log_path2 + "/")

# Lancement du logger
logactivity = os.path.join(log_path2, ("Audit.log"))
print("logactivity {}".format(logactivity))
logger, file_handler = logactivityinit(logactivity)
logactivityinit(logactivity)
log_file = logactivity
logger.info("Début du script d'audit")
user_script_pass = getpass.getpass("Merci de renseigner le mot de passe de {} ".format(user_script)) # pass du user admaic

################# Lancement sur une seule machine ############################# 
if sys.argv[1] == "-s":
    logger.info("Option choisi : {}".format(sys.argv[1]))
    remote_hostname = sys.argv[2]
    logger.info("Le script s'éxécutera sur {}".format(remote_hostname))
    
    #Check si la machine réponds à son nom/ip et utilisation de la méthode fonctionnelle
    remote_hostname = is_online(remote_hostname)
    # Si remote_hostname n'a pas de valeur(ping KO) on exit le script
    if not remote_hostname:
        logger.critical("Exit du script car la machine ne réponds pas")
        exit()
    #Récupération OS/Version/Kernel machines (Debian/Ubuntu)
    infos_machine = get_os_version(remote_hostname)
    # Vérifie si la machine est à jour sur le site(debian/ubuntu)
    get_last_patch(infos_machine)

    # Récupération des users
    users = get_users(remote_hostname)
    # Analyse de l'history
    get_history(remote_hostname,users)

    choix = input("Avez-vous l'accord du RSSI pour l'audit des password ? Y/N : ") # Audit password necessite accord RSSI
    if choix == "Y":
        rssi_pass = getpass.getpass("Mot de passe d'AUDIT ? : ").encode('utf-8')
        rssi_pass = b.b64encode(rssi_pass) # pass du rssi
        if rssi_pass.decode('utf-8') == rssi: # on déchiffre et on compare
            logger.info("Audit en cours par dictionnaire")
            shadow = get_shadow(remote_hostname,users)
            shadow_file = temp_pass(shadow,remote_hostname)
            vitesse = input("Rapide (3600 mots) ou Lent (14Million de mots) ? R/L : ")
            logger.info("Les mot de passes n'apparaitront ni dans la console ni dans le logger")
            liste_cracked = jtr(vitesse,shadow_file)
            if liste_cracked == False:
                logger.critical("Audit mot de passe KO sur : %s" % (remote_hostname))
            else:
                password_is_weak(liste_cracked)
            try:
                os.remove(log_path2+"/"+shadow_file)
                logger.info("Suppression du fichier temporaire OK")
            except:
                logger.critical("Erreur au niveau de la suppression de {}".format(shadow_file))

        else:
            logger.critical("Mauvais mot de passe RSSI")
            exit()
    else:
        logger.info("Fin du script d'Audit")

########## Lancement par lot de machines ####################    
elif sys.argv[1] == "-l": # si lot de machines
    logger.info("Option choisi : {}".format(sys.argv[1]))
    # on s'assure que le fichier est bien readable
    try: 
        with open(sys.argv[2], "r") as f:
            nb = f.readlines()
            nb = len(nb)
            f.close
    except:
        logger.critical("Fichier de lots introuvable")
        exit()
    with open(sys.argv[2], "r") as f: # on réouvre le fichier pour travailler
        i = 0 # compteur
        for srv in f: # itération pour chaque srv
            i = i + 1 # compteur du serveur
            srv = str(srv).split("\n")[0] # récup hostname 
            remote_hostname = srv
            logger.info("Traitement serveur :  {}/{} : {} ".format(i,nb,remote_hostname)) # format exemple : Traitement serveur 12/145 : serveurdns
    
            #Check si la machine réponds à son nom/ip et utilisation de la méthode fonctionnelle
            remote_hostname = is_online(remote_hostname)
                # Si remote_hostname n'a pas de valeur(ping KO) on exit le script
            if not remote_hostname:
                logger.critical("Machine ne réponds pas -> saut de boucle")
                continue
            #Récupération OS/Version/Kernel machines (Debian/Ubuntu)
            infos_machine = get_os_version(remote_hostname)
            # Vérifie si la machine est à jour sur le site(debian/ubuntu)
            get_last_patch(infos_machine)

            # Récupération des users
            users = get_users(remote_hostname)
            # Analyse de l'history
            get_history(remote_hostname,users)

            choix = input("Avez-vous l'accord du RSSI pour l'audit des password ? Y/N : ") # Necessite accord rssi
            if choix == "Y":
                rssi_pass = getpass.getpass("Mot de passe d'AUDIT ? : ").encode('utf-8')
                rssi_pass = b.b64encode(rssi_pass) # chiffrement pass
                if rssi_pass.decode('utf-8') == rssi: # déchiffrement rsssi voir variables en haut
                    logger.info("Audit en cours par dictionnaire")
                    shadow = get_shadow(remote_hostname,users)
                    shadow_file = temp_pass(shadow,remote_hostname)
                    vitesse = input("Rapide (3600 mots) ou Lent (14Million de mots) ? R/L : ")
                    logger.info("Les mot de passes n'apparaitront ni dans la console ni dans le logger")
                    liste_cracked = jtr(vitesse,shadow_file)
                    if liste_cracked == False:
                        logger.critical("Audit mot de passe KO sur : %s" % (remote_hostname))
                    else:
                        password_is_weak(liste_cracked)
                    try:
                        os.remove(log_path2+"/"+shadow_file)
                        logger.info("Suppression du fichier temporaire OK")
                    except:
                        logger.critical("Erreur au niveau de la suppression de {}".format(shadow_file))
                else:
                    logger.critical("Mauvais mot de passe RSSI")
                    exit()
            else:
                logger.info("Fin du script d'Audit")

logger.info("Close du logger pour sendmail")

logactivityclose(file_handler, logactivity, log_path, logger)
SendMailIT(log_file)


