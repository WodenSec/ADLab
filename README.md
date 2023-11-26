# ADLab

## Mise en place du lab

### Setup des VM
- Récupérer les ISO
  - [Windows 10 Enterprise](https://info.microsoft.com/ww-landing-windows-10-enterprise.html?lcid=fr)
  - [Windows Server 2022](https://www.microsoft.com/fr-fr/evalcenter/evaluate-windows-server-2022 )
- Créer les VM dans un hyperviseur en les nommant DC01 et PC01
  - Recommandé: 4GB de RAM, 2 CPU
  - Minimum: 3GB de RAM, 1 CPU
  - Disque: 50GB dynamique
- Changer les paramètres réseaux pour que les VM puissent communiquer entre elles (avec Kali également)
  - VirtualBox: NAT Network
  - VMWare: Custom (VMNet8)
 
### Setup du DC
- Lancer le DC, installer Windows (choisir Standard & "Expérience de bureau")
- Choisir l'installation personnalisée, sélectionner le disque et laisser faire l'installation et le redémarrage
- Entrer le mot de passe `R00tR00t` pour l'utilisateur `Administrateur`
- Se connecter et installer les VM Tools / Guest Additions puis éteindre
- Récupérer le script `Set-DC01` et le "dot-source" avec la commande `. .\Set-DC01.ps1`
- Lancer la fonction `Invoke-DCSetup`
- Le script va redémarrer le serveur deux fois. Il faut donc lancer la même fonction trois fois en tout

### Setup du PC
- Une fois le DC configuré, lancer le PC et installer Windows
- Utiliser les credentials suivantes pour la configuration: `installpc` / `Superadministrat0r!`
- Installer les VM Tools / Guest Additions puis redémarrer
- Récupérer le script `Set-PC01` et le "dot-source" avec la commande `. .\Set-PC01.ps1`
- Lancer la fonction `Set-PC01`
- Le script va redémarrer l'ordinateur une fois. Il faut lancer la même fonction deux fois en tout

### Snapshots
- Une fois que le DC et PC sont configurés, faire un snapshot des deux VM

## Notes

Merci à [Dewalt](https://github.com/Dewalt-arch) pour son script [pimpmyadlab](https://github.com/Dewalt-arch/pimpmyadlab/tree/main). 
