# ADLab

## Mise en place du lab Active Directory

**LIRE ATTENTIVEMENT TOUTES LES ÉTAPES AVANT DE COMMENCER.**
**NE FAITES PAS D'ACTIONS MANUELLES TELLES QUE RENOMMER LES MACHINES OU AJOUTER DES RÔLES.**

### Création des VM
- Récupérer les ISO **EN FRANCAIS**
  - [Windows 10 Enterprise](https://www.microsoft.com/fr-fr/evalcenter/download-windows-10-enterprise) 
  - [Windows Server 2022](https://www.microsoft.com/fr-fr/evalcenter/download-windows-server-2022)
- Créer les VM dans un hyperviseur en les nommant DC01, PC01 & PC02.
  - Pour VirtualBox, ajouter le fichier ISO. **Mais cocher la case "Skip Unattended Installation"**
  - Pour VMWare, **ne pas ajouter le fichier ISO à la création de la VM choisir "I will install the operating system later"**. Puis ajouter l'ISO dans le lecteur CD quand la VM est créée.
- Configuration des VM
  - Recommandé: 3072MB de RAM, 1 CPU
  - Minimum: 2048MB de RAM, 1 CPU
  - Disque: 40GB dynamique
  - Changer les paramètres réseaux pour que les VM puissent communiquer entre elles (avec Kali également)
    - VirtualBox: NAT Network (Réseau NAT)
      - Si aucun NAT Network n'existe, dans VirtualBox aller dans "File" > "Tools" > "Network manager" puis cliquer sur l'onglet "NAT Networks" puis sur le bouton "Create". Il sera ensuite possible d'assigner un NAT Network aux VM.
    - VMWare: Custom (VMNet8)
 
### Setup du DC
- Allumer la VM DC01, installer Windows (choisir **Standard & "Expérience de bureau"**)
- Choisir l'installation personnalisée, sélectionner le disque et laisser faire l'installation et le redémarrage
- Utiliser le mot de passe `R00tR00t` pour l'utilisateur `Administrateur`
- Se connecter et installer les VM Tools / Guest Additions puis redémarrer.
- Récupérer le script `Set-DC01`
-   Pour cela, ouvrir l'URL suivante : https://raw.githubusercontent.com/WodenSec/ADLab/main/Set-DC01.ps1
-   Copier l'intégralité du script puis le coller dans un fichier sur le DC. Renommer ce fichier en `Set-DC01.ps1`
- Ouvrir PowerShell en admin, ensuite taper la commande `powershell -ep bypass`
- Se placer dans le répertoire contenant le script et lancer la commande `. .\Set-DC01.ps1`
- Lancer la fonction `Invoke-DCSetup`
- Le script va faire redémarrer le serveur.
- Refaire les commandes pour executer le script. C'est à dire:
  - Ouvrir PowerShell en admin, ensuite taper la commande `powershell -ep bypass`
  - Se placer dans le répertoire contenant le script et lancer la commande `. .\Set-DC01.ps1`
  - Lancer la fonction `Invoke-DCSetup`
- Ensuite, le serveur va de nouveau redémarrer. Cette fois il faut se connecter avec le compte `Administrateur` dans le domain `WODENSEC.local` et relancer le script une dernière fois en faisant les mêmes 3 étapes citées plus haut.

```
$c = @{ '1' = 'nevagroup-dc'; '2' = 'nevasec-dc'; '3' = 'srv-app' }; $s = Read-Host "Machine à installer:`n1. DC racine (nevagroup-dc)`n2. DC sous-domaine (nevasec-dc)`n3. Serveur standard (srv-app)`nEntrez votre choix (1/2/3):"; if ($c.ContainsKey($s)) { (iwr -useb ("https://raw.githubusercontent.com/WodenSec/ADLab/main/" + $c[$s] + ".ps1")) | iex; Invoke-LabSetup } else { Write-Host "Choix invalide." }
```

#### Configuration manuelle sur le DC

Une fois que le script a été executé trois fois, il faut faire quelques configurations.

##### Ajout de permissions
- Aller dans `Utilisateurs et ordinateurs Active Directory`
- Dans `Affichage`, cliquer sur `Fonctionnalités avancées`
- Cliquer droit sur `WODENSEC.local` dans l'arborescence et cliquer `Propriétés`
- Dans l'onglet `Sécurité`, `Ajouter...` ajouter le groupe `Backup`
- Sélectionner le groupe `Backup` et Autoriser les permissions `Réplication de toutes les modifications de l'annuaire`, `Réplication des changements de répertoire` et `Réplication des changements de répertoires dans un ensemble filtré`

##### Ajout d'un template de certificat
- Cliquer sur Démarrer et chercher "cert" puis cliquer sur `Autorité de certification`
- Dérouler la liste sous `WODENSEC-DC01-CA` puis faire clic-droit sur `Modèles de certificats` et cliquer sur `Gérer`
- Clic-droit sur le modèle `Utilisateur` puis `Dupliquer le modèle`
- Dans l'onglet `Général` donner le nom `VPNCert` au modèle
- Dans l'onglet `Nom du sujet` cliquer sur `Fournir dans la demande`
- Cliquer sur `Appliquer` puis `OK`
- Revenir sur la fenête d'autorité de certification (certsrv) et faire clic-droit sur `Modèles de certificats` > `Nouveau` > `Modèle de certificat à délivrer`
- Dans la liste choisir `VPNCert` puis `OK`

### Autre

- Ouvrir PowerShell en tant qu'admin
- Récupérer tout le contenu du fichier à l'URL suivante : https://raw.githubusercontent.com/WodenSec/ADLab/main/fix.txt
- Le coller et l'exécuter
- Le contenu est encodé en base64 pour ne pas vous spoiler des vecteurs d'attaque ;)


### Setup des PC
- Une fois le DC configuré, lancer le PC et installer Windows
- Sélectionner "Joindre le domaine à la place" pour la création du compte.
- Utiliser les login/mdp suivants pour l'utilisateur local: `installpc` / `Sysadmin123!`
- Installer les VM Tools / Guest Additions puis redémarrer
- Ouvrir PowerShell en admin, ensuite taper la commande `powershell -ep bypass`
- Récupérer le script `Set-PC01` et le "dot-source" avec la commande `. .\Set-PC01.ps1`
- Lancer la fonction `Invoke-PC01Setup`
- Le script va redémarrer l'ordinateur une fois. Il faut lancer la même fonction deux fois en tout

> Si vos ressources (RAM,CPU) le permettent, créer un deuxième PC de la même manière avec `Set-PC02`

### Snapshots
- Une fois que le DC et PC sont configurés, faire un snapshot des VM

## Setup Kali
- Importer la Kali en double cliquant sur le fichier `.ova` pour VirtualBox et `.vmx` pour VMWare
- Changer la carte réseau en l'attribuant au NAT Network pour VirtualBox ou Custom (VMNet8) pour VMWare
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
