# ADLab

## Mise en place du lab Active Directory

**LIRE ATTENTIVEMENT TOUTES LES ETAPES AVANT DE COMMENCER**

### Setup des VM
- Récupérer les ISO **EN FRANCAIS**
  - [Windows 10 Enterprise](https://www.microsoft.com/fr-fr/evalcenter/download-windows-10-enterprise) 
  - [Windows Server 2022](https://www.microsoft.com/fr-fr/evalcenter/download-windows-server-2022)
- Créer les VM dans un hyperviseur en les nommant DC01, PC01 & PC02
  - Pour VirtualBox, cocher **"Skip Unattended Installation"**
  - Pour VMWare, choisir **I will install the operating system later** et ensuite seulement insérer l'ISO dans le DVD drive
  - Recommandé: 4GB de RAM, 1 ou 2 CPU
  - Minimum: 2GB de RAM, 1 CPU
  - Disque: 50GB dynamique
- Changer les paramètres réseaux pour que les VM puissent communiquer entre elles (avec Kali également)
  - VirtualBox: NAT Network
  - VMWare: Custom (VMNet8)
 
### Setup du DC
- Lancer le DC, installer Windows (choisir Standard & "Expérience de bureau")
- Choisir l'installation personnalisée, sélectionner le disque et laisser faire l'installation et le redémarrage
- Entrer le mot de passe `R00tR00t` pour l'utilisateur `Administrateur`
- Se connecter et installer les VM Tools / Guest Additions puis redémarrer.
- Ouvrir PowerShell en admin, ensuite taper la commande `powershell -ep bypass`
- Récupérer le script `Set-DC01`, se placer dans le répertoire contenant le script et lancer la commande `. .\Set-DC01.ps1`
- Lancer la fonction `Invoke-DCSetup`
- Le script va redémarrer le serveur. Il faut le relancer en utilisant les mêmes commandes un deuxième fois.
- Ensuite, le serveur va de nouveau redémarrer. Cette fois il faut se connecter avec le compte `Administrateur` dans le domain `WODENSEC.local` et relancer le script une dernière fois.

#### Configuration manuelle sur le DC

- Aller dans `Utilisateurs et ordinateurs Active Directory`
- Dans `Affichage`, cliquer sur `Fonctionnalités avancées`
- Cliquer droit sur `WODENSEC.local` dans l'arborescence et cliquer `Propriétés`
- Dans l'onglet `Sécurité`, `Ajouter...` ajouter le groupe `Backup`
- Sélectionner le groupe `Backup` et Autoriser les permissions `Réplication de toutes les modifications de l'annuaire`, `Réplication des changements de répertoire` et `Réplication des changements de répertoires dans un ensemble filtré`

- Cliquer sur Démarrer et chercher "cert" puis cliquer sur `Autorité de certification`
- Dérouler la liste sous `WODENSEC-DC01-CA` puis faire clic-droit sur `Modèles de certificats` et cliquer sur `Gérer`
- Clic-droit sur le modèle `Utilisateur` puis `Dupliquer le modèle`
- Dans l'onglet `Général` donner le nom `VPNCert` au modèle
- Dans l'onglet `Nom du sujet` cliquer sur `Fournir dans la demande`
- Cliquer sur `Appliquer` puis `OK`
- Revenir sur la fenête d'autorité de certification (certsrv) et faire clic-droit sur `Modèles de certificats` > `Nouveau` > `Modèle de certificat à délivrer`
- Dans la liste choisir `VPNCert` puis `OK`

### Setup des PC
- Une fois le DC configuré, lancer le PC et installer Windows
- Sélectionner "Joindre le domaine à la place" pour la création du compte.
- Utiliser les credentials suivantes pour la configuration: `installpc` / `Sysadmin123!`
- Installer les VM Tools / Guest Additions puis redémarrer
- Ouvrir PowerShell en admin, ensuite taper la commande `powershell -ep bypass`
- Récupérer le script `Set-PC01` et le "dot-source" avec la commande `. .\Set-PC01.ps1`
- Lancer la fonction `Invoke-PC01Setup`
- Le script va redémarrer l'ordinateur une fois. Il faut lancer la même fonction deux fois en tout

> Si vos ressources (RAM,CPU) le permettent, créer un deuxième PC de la même manière avec `Set-PC02`

### Snapshots
- Une fois que le DC et PC sont configurés, faire un snapshot des VM

## Setup Kali
- Se connecter avec les identifiants `kali` / `kali`
- Ouvrir un terminal et lancer la command `setxkbmap fr`
- Lancer la commande `sudo nano /etc/default/keyboard` et changer le `us` en `fr`
- Lancer la commande `sudo apt update`
- Lancer les commandes `cd /opt` puis `sudo git clone https://github.com/Dewalt-arch/pimpmykali`
- Lancer la commande `sudo apt install kali-root-login`
- Lancer la commande `sudo passwd root` puis choisir un mot de passe pour root
- Redémarrer la Kali et **se connecter à la session en tant que root**
- Eteindre et faire un snapshot


## Notes

Merci à [Dewalt](https://github.com/Dewalt-arch) pour son script [pimpmyadlab](https://github.com/Dewalt-arch/pimpmyadlab/tree/main). 
