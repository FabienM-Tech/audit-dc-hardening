<h1 align="center">Auditeur de durcissement de contrôleur de domaine</h1>

<p align="center">
  <em>Un script PowerShell qui audite un contrôleur de domaine Active Directory, attribue une note de sécurité et génère un rapport HTML avec les corrections à appliquer.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-5391FE?style=flat&logo=powershell&logoColor=white"/>
  <img src="https://img.shields.io/badge/Active_Directory-0078D6?style=flat&logo=microsoft&logoColor=white"/>
  <img src="https://img.shields.io/badge/Sécurité-Durcissement-red?style=flat&logo=hackthebox&logoColor=white"/>
  <img src="https://img.shields.io/badge/Rapport-HTML-orange?style=flat&logo=html5&logoColor=white"/>
</p>

---

## En bref

`Audit-DCHardening.ps1` est un **vrai script PowerShell** (pas un générateur) qui exécute une série de **contrôles de sécurité** sur un contrôleur de domaine Windows Server. Chaque point de contrôle reçoit une **criticité** (Critique / Élevée / Moyenne / Faible), l'outil calcule un **score de durcissement pondéré**, puis produit un **rapport HTML** listant, pour chaque non-conformité, la **procédure de correction** (commande PowerShell et/ou chemin de GPO).

C'est l'outil idéal pour objectiver l'état de sécurité d'un AD, prioriser les actions et documenter une démarche de durcissement.

## Ce que le script vérifie

Près de **40 contrôles** répartis en **8 catégories** :

| Catégorie | Exemples de contrôles |
|-----------|------------------------|
| **Politique de mots de passe** | Longueur minimale, complexité, historique, seuil de verrouillage, âge du compte `krbtgt` |
| **Protocoles legacy** | SMBv1, LLMNR, NetBIOS, signature SMB, spouleur d'impression |
| **LDAP / Kerberos** | Signature LDAP, channel binding, chiffrements Kerberos faibles, restriction NTLM, accès anonyme |
| **Comptes privilégiés** | Compte Invité, taille de Domain Admins, Protected Users, LAPS, corbeille AD |
| **Audit et journalisation** | Stratégies d'audit avancées, taille du journal de sécurité, journalisation des ouvertures de session et des comptes |
| **Réseau et services** | Pare-feu Windows, NLA (RDP), WinRM HTTPS, source de temps NTP, mises à jour DNS sécurisées |
| **Infrastructure AD** | Niveau fonctionnel du domaine, GPO des contrôleurs, permissions SYSVOL/NETLOGON |
| **Durcissement système & endpoint** | LSA Protection (RunAsPPL), Defender, AppLocker, services superflus, WSUS, BitLocker |

## Prérequis

- Un **contrôleur de domaine** Windows Server (ou un poste avec le module **ActiveDirectory** RSAT et les droits suffisants).
- **PowerShell 5.1** ou supérieur.
- Exécution en tant qu'**administrateur** (le script propose une **auto-élévation UAC** au lancement).

## Guide d'utilisation pas à pas

1. **Téléchargez** `Audit-DCHardening.ps1` sur le contrôleur de domaine.
2. Clic droit sur le fichier → **« Exécuter avec PowerShell »**. Le script se **relance automatiquement en administrateur** (acceptez l'invite UAC).
   - Ou en ligne de commande : `.\Audit-DCHardening.ps1`
3. Laissez les contrôles s'exécuter. À la fin, le **rapport HTML** est généré (par défaut dans `…\Desktop\Audit-DC`).
4. Ouvrez le rapport : consultez le **score global**, puis parcourez chaque non-conformité et sa **procédure de correction**.

### Options

| Paramètre | Rôle | Exemple |
|-----------|------|---------|
| `-OutputPath` | Dossier de sortie du rapport | `.\Audit-DCHardening.ps1 -OutputPath "C:\Audit"` |
| `-OpenReport` | Ouvre le rapport automatiquement à la fin | `.\Audit-DCHardening.ps1 -OpenReport` |

## Avertissement

Cet outil est **en lecture seule** : il **audite** mais ne modifie rien sur le système. Les corrections proposées, elles, changent la configuration : appliquez-les avec discernement et **testez en environnement de laboratoire** avant la production. Conçu à des fins **pédagogiques** (TP AD / durcissement).

---

<p align="center"><em>Automatiser · Standardiser · Sécuriser</em></p>
