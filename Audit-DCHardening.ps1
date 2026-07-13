#Requires -Version 5.1
<#
.SYNOPSIS
    Outil d'audit de durcissement pour contrôleur de domaine Windows Server (Active Directory).

.DESCRIPTION
    Exécute une série de contrôles de sécurité sur un contrôleur de domaine, attribue une
    criticité à chaque point de contrôle (Critique / Élevée / Moyenne / Faible), calcule un
    score de durcissement pondéré et génère un rapport HTML détaillé avec, pour chaque
    non-conformité, une procédure de correction (commande PowerShell et/ou chemin de GPO).

.NOTES
    À exécuter en tant qu'administrateur, directement sur le contrôleur de domaine
    (ou sur un poste disposant du module ActiveDirectory RSAT + droits suffisants).
    Auteur   : Outil généré pour usage pédagogique (TP AD / durcissement)
    Version  : 1.0

.EXAMPLE
    .\Audit-DCHardening.ps1
    .\Audit-DCHardening.ps1 -OutputPath "C:\Audit" -OpenReport
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop\Audit-DC",
    [switch]$OpenReport
)

# ============================================================================
#  AUTO-ÉLÉVATION (relance en administrateur si nécessaire)
# ============================================================================
# Permet le clic droit > « Exécuter avec PowerShell » : le script se relance
# automatiquement dans une console administrateur (invite UAC), puis l'instance
# non privilégiée se ferme.
$__principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $__principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($PSCommandPath) {
        Write-Host "Ce script requiert des droits administrateur. Élévation en cours (UAC)..." -ForegroundColor Yellow
        try {
            $__psExe = (Get-Process -Id $PID).Path        # powershell.exe (ou pwsh.exe) en cours
            if (-not $__psExe) { $__psExe = 'powershell.exe' }
            $__args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath),'-OpenReport')
            if ($OutputPath) { $__args += @('-OutputPath',('"{0}"' -f $OutputPath)) }
            Start-Process -FilePath $__psExe -Verb RunAs -ArgumentList $__args | Out-Null
        } catch {
            Write-Warning "Élévation refusée ou impossible : $($_.Exception.Message)"
            Read-Host "Appuyez sur Entrée pour fermer"
        }
        exit
    }
}

# Filet de sécurité : garder la fenêtre ouverte si une erreur non gérée interrompt le script
trap {
    Write-Host "`n[ERREUR NON GÉRÉE] $($_.Exception.Message)" -ForegroundColor Red
    Read-Host "Appuyez sur Entrée pour fermer cette fenêtre"
    exit 1
}

# ============================================================================
#  INITIALISATION
# ============================================================================

$ErrorActionPreference = 'Stop'
$ScriptStart = Get-Date

if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Warning "Ce script doit être exécuté en tant qu'Administrateur pour des résultats fiables. Certains contrôles vont échouer ou remonter 'Erreur'."
}

$ADModuleOK = $false
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $ADModuleOK = $true
} catch {
    Write-Warning "Module ActiveDirectory introuvable. Les contrôles liés à l'annuaire seront marqués en erreur. Installe RSAT-AD-PowerShell (Install-WindowsFeature RSAT-AD-PowerShell)."
}

$GPModuleOK = $false
try {
    Import-Module GroupPolicy -ErrorAction Stop
    $GPModuleOK = $true
} catch { }

$DnsModuleOK = $false
try {
    Import-Module DnsServer -ErrorAction Stop
    $DnsModuleOK = $true
} catch { }

# ============================================================================
#  MOTEUR DE CONTRÔLE
# ============================================================================

$Global:Results = New-Object System.Collections.Generic.List[PSObject]

$Weights = @{
    'Critique' = 10
    'Élevée'   = 6
    'Moyenne'  = 3
    'Faible'   = 1
}

function Add-Check {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Critique','Élevée','Moyenne','Faible')][string]$Criticality,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Test,        # doit retourner un hashtable @{Pass=$bool; Current='...'; Expected='...'}
        [Parameter(Mandatory)][string]$Remediation,       # commandes / étapes de correction
        [string]$GpoPath = ''
    )

    $status = 'Erreur'
    $current = 'N/A'
    $expected = 'N/A'
    $errMsg = $null

    try {
        $r = & $Test
        $status = if ($r.Pass) { 'Conforme' } else { 'Non conforme' }
        $current = $r.Current
        $expected = $r.Expected
    } catch {
        $status = 'Erreur'
        $errMsg = $_.Exception.Message
    }

    $Global:Results.Add([PSCustomObject]@{
        Id          = $Id
        Category    = $Category
        Name        = $Name
        Criticality = $Criticality
        Description = $Description
        Status      = $status
        Current     = $current
        Expected    = $expected
        Remediation = $Remediation
        GpoPath     = $GpoPath
        Error       = $errMsg
    })
}

# Helper pour lire les valeurs de registre sans planter si absentes
function Get-RegValue {
    param([string]$Path, [string]$Name, $Default = $null)
    try {
        $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $v.$Name
    } catch {
        return $Default
    }
}

Write-Host "`n=== Audit de durcissement du contrôleur de domaine en cours ===`n" -ForegroundColor Cyan
Write-Host "Hôte : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "Date : $($ScriptStart.ToString('dd/MM/yyyy HH:mm:ss'))`n" -ForegroundColor Gray

# ============================================================================
#  CATÉGORIE 1 : POLITIQUE DE MOTS DE PASSE ET VERROUILLAGE
# ============================================================================

Add-Check -Id 'PWD-01' -Category 'Politique de mots de passe' -Name 'Longueur minimale du mot de passe' `
    -Criticality 'Élevée' `
    -Description "La longueur minimale du mot de passe du domaine doit être d'au moins 14 caractères." `
    -Test {
        if (-not $ADModuleOK) { throw "Module AD indisponible" }
        $pol = Get-ADDefaultDomainPasswordPolicy
        @{ Pass = ($pol.MinPasswordLength -ge 14); Current = "$($pol.MinPasswordLength) caractères"; Expected = ">= 14 caractères" }
    } `
    -Remediation "Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -MinPasswordLength 14" `
    -GpoPath "Default Domain Policy > Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Stratégies de compte > Stratégie de mot de passe > Longueur minimale du mot de passe"

Add-Check -Id 'PWD-02' -Category 'Politique de mots de passe' -Name 'Complexité du mot de passe activée' `
    -Criticality 'Élevée' `
    -Description "La complexité du mot de passe doit être activée." `
    -Test {
        if (-not $ADModuleOK) { throw "Module AD indisponible" }
        $pol = Get-ADDefaultDomainPasswordPolicy
        @{ Pass = ($pol.ComplexityEnabled -eq $true); Current = $pol.ComplexityEnabled; Expected = "True" }
    } `
    -Remediation "Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -ComplexityEnabled `$true" `
    -GpoPath "Default Domain Policy > Stratégies de compte > Stratégie de mot de passe > Le mot de passe doit respecter des exigences de complexité"

Add-Check -Id 'PWD-03' -Category 'Politique de mots de passe' -Name "Historique des mots de passe" `
    -Criticality 'Moyenne' `
    -Description "Au moins 24 mots de passe doivent être mémorisés dans l'historique." `
    -Test {
        if (-not $ADModuleOK) { throw "Module AD indisponible" }
        $pol = Get-ADDefaultDomainPasswordPolicy
        @{ Pass = ($pol.PasswordHistoryCount -ge 24); Current = $pol.PasswordHistoryCount; Expected = ">= 24" }
    } `
    -Remediation "Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -PasswordHistoryCount 24" `
    -GpoPath "Default Domain Policy > Stratégies de compte > Stratégie de mot de passe > Conserver l'historique des mots de passe"

Add-Check -Id 'PWD-04' -Category 'Politique de mots de passe' -Name 'Seuil de verrouillage du compte' `
    -Criticality 'Élevée' `
    -Description "Le compte doit se verrouiller après un nombre limité de tentatives (1 à 10)." `
    -Test {
        if (-not $ADModuleOK) { throw "Module AD indisponible" }
        $pol = Get-ADDefaultDomainPasswordPolicy
        $th = $pol.LockoutThreshold
        @{ Pass = ($th -gt 0 -and $th -le 10); Current = $th; Expected = "Entre 1 et 10 (jamais 0)" }
    } `
    -Remediation "Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -LockoutThreshold 5 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00" `
    -GpoPath "Default Domain Policy > Stratégies de compte > Stratégie de verrouillage du compte > Seuil de verrouillage du compte"

Add-Check -Id 'PWD-05' -Category 'Politique de mots de passe' -Name 'Âge du mot de passe krbtgt' `
    -Criticality 'Critique' `
    -Description "Le mot de passe du compte krbtgt doit être renouvelé régulièrement (idéalement tous les 180 jours, deux fois de suite avec un délai de propagation)." `
    -Test {
        if (-not $ADModuleOK) { throw "Module AD indisponible" }
        $krbtgt = Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet
        $ageDays = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days
        @{ Pass = ($ageDays -le 180); Current = "$ageDays jours"; Expected = "<= 180 jours" }
    } `
    -Remediation "Utiliser le script officiel Microsoft 'New-KrbtgtKeys.ps1' (rotation en 2 passes espacées d'au moins la durée de vie max des tickets Kerberos). Ne JAMAIS faire un simple Reset-ADAccountPassword répété sans respecter le délai de réplication." `
    -GpoPath "N/A (opération manuelle planifiée, hors GPO)"

# ============================================================================
#  CATÉGORIE 2 : PROTOCOLES ET SERVICES LEGACY
# ============================================================================

Add-Check -Id 'PROTO-01' -Category 'Protocoles legacy' -Name 'SMBv1 désactivé' `
    -Criticality 'Critique' `
    -Description "Le protocole SMBv1, obsolète et vulnérable (EternalBlue/WannaCry), doit être désactivé." `
    -Test {
        $feat = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop
        @{ Pass = ($feat.State -eq 'Disabled'); Current = $feat.State; Expected = "Disabled" }
    } `
    -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" `
    -GpoPath "GPO dédiée ou registre : HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 = 0"

Add-Check -Id 'PROTO-02' -Category 'Protocoles legacy' -Name 'LLMNR désactivé' `
    -Criticality 'Élevée' `
    -Description "LLMNR (Link-Local Multicast Name Resolution) facilite les attaques de type LLMNR/NBT-NS poisoning (ex. Responder) et doit être désactivé." `
    -Test {
        $v = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Default $null
        @{ Pass = ($v -eq 0); Current = $(if ($null -eq $v) { "Non configuré (activé par défaut)" } else { $v }); Expected = "0 (Désactivé)" }
    } `
    -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -Type DWord" `
    -GpoPath "Computer Configuration > Modèles d'administration > Réseau > Client DNS > Désactiver la résolution de noms multidiffusion"

Add-Check -Id 'PROTO-03' -Category 'Protocoles legacy' -Name 'NetBIOS over TCP/IP désactivé sur l''interface DC' `
    -Criticality 'Moyenne' `
    -Description "NetBIOS doit être désactivé sur les interfaces réseau pour réduire la surface d'attaque NBT-NS." `
    -Test {
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE"
        $notDisabled = $adapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
        @{ Pass = ($notDisabled.Count -eq 0); Current = "$($notDisabled.Count) interface(s) avec NetBIOS actif/défaut"; Expected = "0 interface" }
    } `
    -Remediation "(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE') | ForEach-Object { `$_.SetTcpipNetbios(2) }  # 2 = Désactiver NetBIOS" `
    -GpoPath "Manuel par interface, ou script de démarrage GPO"

Add-Check -Id 'PROTO-04' -Category 'Protocoles legacy' -Name 'Signature SMB obligatoire (serveur)' `
    -Criticality 'Élevée' `
    -Description "La signature SMB côté serveur doit être exigée pour empêcher le relais NTLM/SMB." `
    -Test {
        $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Default 0
        @{ Pass = ($v -eq 1); Current = $v; Expected = "1" }
    } `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord" `
    -GpoPath "Paramètres de sécurité > Options de sécurité > Serveur réseau Microsoft : signer numériquement les communications (toujours)"

Add-Check -Id 'PROTO-05' -Category 'Protocoles legacy' -Name 'Service Spouleur d''impression désactivé sur le DC' `
    -Criticality 'Critique' `
    -Description "Le service Spouleur d'impression doit être désactivé sur les contrôleurs de domaine (vulnérabilités PrintNightmare / CVE-2021-34527 et suivantes)." `
    -Test {
        $svc = Get-Service -Name 'Spooler' -ErrorAction Stop
        @{ Pass = ($svc.Status -eq 'Stopped' -and (Get-Service Spooler).StartType -eq 'Disabled'); Current = "$($svc.Status) / StartType=$((Get-Service Spooler).StartType)"; Expected = "Stopped / Disabled" }
    } `
    -Remediation "Stop-Service -Name Spooler -Force; Set-Service -Name Spooler -StartupType Disabled" `
    -GpoPath "GPO dédiée aux DC : Configuration ordinateur > Modèles d'administration > Imprimantes > Autoriser le spouleur d'impression à accepter les connexions clients = Désactivé, + service désactivé"

# ============================================================================
#  CATÉGORIE 3 : LDAP / KERBEROS / AUTHENTIFICATION
# ============================================================================

Add-Check -Id 'LDAP-01' -Category 'LDAP / Kerberos' -Name 'Signature LDAP exigée' `
    -Criticality 'Critique' `
    -Description "Le serveur LDAP doit exiger la signature des requêtes pour empêcher les attaques de relais LDAP." `
    -Test {
        $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -Default 1
        @{ Pass = ($v -eq 2); Current = $v; Expected = "2 (Exiger la signature)" }
    } `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -Value 2 -Type DWord ; redémarrer le service NTDS ou le serveur" `
    -GpoPath "Default Domain Controllers Policy > Options de sécurité > Serveur réseau Microsoft LDAP : exigences de signature = Exiger la signature"

Add-Check -Id 'LDAP-02' -Category 'LDAP / Kerberos' -Name 'LDAP Channel Binding (canal LDAPS)' `
    -Criticality 'Élevée' `
    -Description "La liaison de canal LDAP (channel binding) doit être exigée pour LDAPS afin de contrer le relais NTLM sur LDAPS (ADV190023)." `
    -Test {
        $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' -Default 0
        @{ Pass = ($v -eq 2); Current = $v; Expected = "2 (Always)" }
    } `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' -Value 2 -Type DWord" `
    -GpoPath "Registre uniquement (voir KB4520412), à déployer via GPP/registre"

Add-Check -Id 'KRB-01' -Category 'LDAP / Kerberos' -Name 'Types de chiffrement Kerberos faibles désactivés' `
    -Criticality 'Critique' `
    -Description "DES et RC4 doivent être exclus ; seuls AES128/AES256 doivent être autorisés pour Kerberos." `
    -Test {
        $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name 'SupportedEncryptionTypes' -Default $null
        # 0x18 = AES128+AES256 uniquement ; toute valeur incluant DES(0x1,0x2) ou RC4(0x4) est non conforme
        $pass = ($null -ne $v) -and (($v -band 0x1) -eq 0) -and (($v -band 0x2) -eq 0) -and (($v -band 0x4) -eq 0) -and (($v -band 0x18) -gt 0)
        @{ Pass = $pass; Current = $(if ($null -eq $v) { "Non configuré (RC4 autorisé par défaut)" } else { "0x{0:X}" -f $v }); Expected = "0x18 (AES128 + AES256 uniquement)" }
    } `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name 'SupportedEncryptionTypes' -Value 24 -Type DWord  # 24 = 0x18 = AES128+AES256" `
    -GpoPath "Default Domain Controllers Policy > Options de sécurité > Sécurité réseau : configurer les types de chiffrement autorisés pour Kerberos"

Add-Check -Id 'AUTH-01' -Category 'LDAP / Kerberos' -Name 'Restriction NTLM entrant' `
    -Criticality 'Moyenne' `
    -Description "L'authentification NTLM entrante doit être auditée voire refusée au profit de Kerberos." `
    -Test {
        $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictReceivingNTLMTraffic' -Default 0
        @{ Pass = ($v -ge 1); Current = $v; Expected = ">= 1 (Auditer ou Refuser)" }
    } `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictReceivingNTLMTraffic' -Value 1 -Type DWord  # commencer par l'audit avant blocage complet" `
    -GpoPath "Default Domain Controllers Policy > Options de sécurité > Sécurité réseau : restreindre le trafic NTLM entrant"

Add-Check -Id 'AUTH-02' -Category 'LDAP / Kerberos' -Name 'Accès anonyme restreint (RestrictAnonymous)' `
    -Criticality 'Élevée' `
    -Description "Les sessions anonymes ne doivent pas pouvoir énumérer les comptes et partages SAM." `
    -Test {
        $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Default 0
        @{ Pass = ($v -ge 1); Current = $v; Expected = ">= 1" }
    } `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1 -Type DWord" `
    -GpoPath "Options de sécurité > Accès réseau : ne pas autoriser l'énumération anonyme des comptes et partages SAM"

# ============================================================================
#  CATÉGORIE 4 : COMPTES ET GROUPES PRIVILÉGIÉS
# ============================================================================

Add-Check -Id 'ACC-01' -Category 'Comptes privilégiés' -Name 'Compte Invité désactivé' `
    -Criticality 'Moyenne' `
    -Description "Le compte Invité du domaine doit être désactivé." `
    -Test {
        if (-not $ADModuleOK) { throw "Module AD indisponible" }
        $guestSid = "$((Get-ADDomain).DomainSID.Value)-501"   # compte Invité (RID 501, indépendant de la langue)
        $g = Get-ADUser -Identity $guestSid -Properties Enabled
        @{ Pass = (-not $g.Enabled); Current = $(if ($g.Enabled) { "Activé" } else { "Désactivé" }); Expected = "Désactivé" }
    } `
    -Remediation "Disable-ADAccount -Identity `"$((Get-ADDomain).DomainSID.Value)-501`"   # compte Invité (RID 501)" `
    -GpoPath "N/A (propriété du compte)"

Add-Check -Id 'ACC-02' -Category 'Comptes privilégiés' -Name 'Taille du groupe Domain Admins' `
    -Criticality 'Élevée' `
    -Description "Le groupe Domain Admins doit être limité au strict minimum (idéalement moins de 5 comptes, jamais de comptes de service)." `
    -Test {
        if (-not $ADModuleOK) { throw "Module AD indisponible" }
        $daSid = "$((Get-ADDomain).DomainSID.Value)-512"   # Domain Admins (indépendant de la langue)
        $members = @(Get-ADGroupMember -Identity $daSid -Recursive)
        @{ Pass = ($members.Count -le 5); Current = "$($members.Count) membre(s)"; Expected = "<= 5 membres" }
    } `
    -Remediation "Revoir manuellement Get-ADGroupMember 'Domain Admins' -Recursive et retirer les comptes non indispensables via Remove-ADGroupMember. Mettre en place un modèle Tier 0 / comptes d'administration dédiés (PAW) et le principe du moindre privilège." `
    -GpoPath "N/A (gouvernance des groupes, à documenter en procédure d'exploitation)"

Add-Check -Id 'ACC-03' -Category 'Comptes privilégiés' -Name 'Groupe Protected Users utilisé' `
    -Criticality 'Faible' `
    -Description "Les comptes à privilèges devraient être membres du groupe 'Protected Users' pour bénéficier de protections Kerberos renforcées (pas de NTLM, pas de délégation, TGT courte durée de vie)." `
    -Test {
        if (-not $ADModuleOK) { throw "Module AD indisponible" }
        $puSid = "$((Get-ADDomain).DomainSID.Value)-525"   # Protected Users (indépendant de la langue)
        $members = @(Get-ADGroupMember -Identity $puSid -ErrorAction SilentlyContinue)
        $count = if ($members) { $members.Count } else { 0 }
        @{ Pass = ($count -gt 0); Current = "$count membre(s)"; Expected = "> 0 (comptes admin critiques inclus)" }
    } `
    -Remediation "Add-ADGroupMember -Identity 'Protected Users' -Members <compte_admin>  # tester en environnement de lab avant prod, impact sur cache identifiants et délégation" `
    -GpoPath "N/A (appartenance de groupe)"

Add-Check -Id 'ACC-04' -Category 'Comptes privilégiés' -Name 'LAPS déployé' `
    -Criticality 'Élevée' `
    -Description "Une solution LAPS (Windows LAPS natif ou legacy AdmPwd) doit gérer les mots de passe administrateur local des postes/serveurs." `
    -Test {
        if (-not $ADModuleOK) { throw "Module AD indisponible" }
        $schemaOk = $false
        try {
            $r = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter "Name -eq 'ms-Mcs-AdmPwd' -or Name -eq 'ms-LAPS-Password'" -ErrorAction Stop
            $schemaOk = ($null -ne $r)
        } catch { $schemaOk = $false }
        @{ Pass = $schemaOk; Current = $(if ($schemaOk) { "Attributs LAPS présents dans le schéma" } else { "Attributs LAPS absents" }); Expected = "Attributs LAPS présents" }
    } `
    -Remediation "Choisir la variante selon l'OS des machines cibles — viser les OU postes/serveurs, PAS les contrôleurs de domaine. [A] Windows Server 2019/2022/2025 + Win10/11 à jour (avril 2023) = Windows LAPS natif : 1) Update-LapsADSchema ; 2) Set-LapsADComputerSelfPermission -Identity 'OU=Serveurs,DC=ymf,DC=lan' (délègue à chaque machine l'écriture de son mot de passe) ; 3) GPO 'Windows LAPS' > Répertoire de sauvegarde du mot de passe = Active Directory, longueur 20, complexité 4 (maj+min+chiffres+spéciaux), âge max 30 j ; 4) gpupdate /force ; 5) consultation : Get-LapsADPassword -Identity <NomPC> -AsPlainText  (rotation immédiate : Reset-LapsPassword). [B] Windows Server 2016 et antérieurs OU machines non patchées = legacy Microsoft LAPS (AdmPwd) : Import-Module AdmPwd.PS ; Update-AdmPwdADSchema ; Set-AdmPwdComputerSelfPermission -OrgUnit 'OU=Serveurs,DC=ymf,DC=lan' ; installer le CSE AdmPwd + GPO LAPS (activer la gestion, longueur/complexité/âge) ; consultation : Get-AdmPwdPassword -ComputerName <NomPC>. NB : ne pas exécuter les deux schémas concurremment ; Windows LAPS natif est la cible recommandée, AdmPwd est en fin de vie." `
    -GpoPath "Computer Configuration > Modèles d'administration > System > LAPS"

Add-Check -Id 'ACC-05' -Category 'Comptes privilégiés' -Name 'Corbeille Active Directory (AD Recycle Bin) activée' `
    -Criticality 'Moyenne' `
    -Description "La Corbeille AD doit être activée pour permettre une restauration rapide d'objets supprimés par erreur ou attaque." `
    -Test {
        if (-not $ADModuleOK) { throw "Module AD indisponible" }
        $feat = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'"
        $enabled = $feat.EnabledScopes.Count -gt 0
        @{ Pass = $enabled; Current = $(if ($enabled) { "Activée" } else { "Désactivée" }); Expected = "Activée" }
    } `
    -Remediation "Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name  # action irréversible, nécessite niveau fonctionnel forêt >= 2008 R2" `
    -GpoPath "N/A (fonctionnalité de forêt)"

# ============================================================================
#  CATÉGORIE 5 : AUDIT ET JOURNALISATION
# ============================================================================

Add-Check -Id 'AUD-01' -Category 'Audit et journalisation' -Name "Audit avancé : Validation des informations d'identification" `
    -Criticality 'Élevée' `
    -Description "Les succès et échecs de validation des identifiants (logon) doivent être audités." `
    -Test {
        $out = auditpol /get /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" 2>$null   # Credential Validation (GUID = indépendant de la langue)
        $text = ($out -join ' ')
        $pass = ($text -match 'Succès et échec' -or $text -match 'Success and Failure')
        @{ Pass = $pass; Current = $text.Trim(); Expected = "Succès et échec activés" }
    } `
    -Remediation "auditpol /set /subcategory:`"Credential Validation`" /success:enable /failure:enable" `
    -GpoPath "Default Domain Controllers Policy > Configuration avancée de la stratégie d'audit > Connexion/déconnexion et Gestion des comptes"

Add-Check -Id 'AUD-02' -Category 'Audit et journalisation' -Name "Audit avancé : Gestion des groupes de sécurité" `
    -Criticality 'Élevée' `
    -Description "Les modifications de groupes de sécurité (ajout/retrait de membres) doivent être auditées." `
    -Test {
        $out = auditpol /get /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030}" 2>$null   # Security Group Management (GUID)
        $text = ($out -join ' ')
        $pass = ($text -match 'Succès' -or $text -match 'Success')
        @{ Pass = $pass; Current = $text.Trim(); Expected = "Succès (a minima) activé" }
    } `
    -Remediation "auditpol /set /subcategory:`"Security Group Management`" /success:enable /failure:enable" `
    -GpoPath "Default Domain Controllers Policy > Configuration avancée de la stratégie d'audit > Gestion des comptes"

Add-Check -Id 'AUD-03' -Category 'Audit et journalisation' -Name "Audit avancé : Accès au service d'annuaire (DS Access)" `
    -Criticality 'Moyenne' `
    -Description "Les modifications d'objets AD sensibles (DS Access) doivent être auditées." `
    -Test {
        $out = auditpol /get /subcategory:"{0CCE923C-69AE-11D9-BED3-505054503030}" 2>$null   # Directory Service Changes (GUID)
        $text = ($out -join ' ')
        $pass = ($text -match 'Succès' -or $text -match 'Success')
        @{ Pass = $pass; Current = $text.Trim(); Expected = "Succès activé" }
    } `
    -Remediation "auditpol /set /subcategory:`"Directory Service Changes`" /success:enable /failure:enable" `
    -GpoPath "Default Domain Controllers Policy > Configuration avancée de la stratégie d'audit > Accès DS"

Add-Check -Id 'AUD-04' -Category 'Audit et journalisation' -Name "Taille du journal de sécurité" `
    -Criticality 'Faible' `
    -Description "Le journal Sécurité doit avoir une taille suffisante (>= 196 Mo recommandé) pour ne pas écraser trop vite les événements." `
    -Test {
        $log = Get-WinEvent -ListLog Security
        $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
        @{ Pass = ($sizeMB -ge 196); Current = "$sizeMB Mo"; Expected = ">= 196 Mo" }
    } `
    -Remediation "wevtutil sl Security /ms:1073741824  # exemple : 1 Go. Idéalement, centraliser aussi les logs vers un SIEM." `
    -GpoPath "Computer Configuration > Modèles d'administration > Composants Windows > Journal d'événements > Sécurité > Taille maximale du journal"

Add-Check -Id 'AUD-05' -Category 'Audit et journalisation' -Name "Audit avancé : Création de processus (4688 + ligne de commande)" `
    -Criticality 'Élevée' `
    -Description "La création de processus (event 4688) doit être auditée AVEC la ligne de commande, pour détecter les attaques LOLBins (powershell, wmic, certutil...)." `
    -Test {
        $out = auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" 2>$null   # Process Creation (GUID)
        $text = ($out -join ' ')
        $auditOn = ($text -match 'Succès' -or $text -match 'Success')
        $cmd = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Default 0
        @{ Pass = ($auditOn -and $cmd -eq 1); Current = "Audit succès : $(if($auditOn){'oui'}else{'non'}) | Ligne de commande : $(if($cmd -eq 1){'capturée'}else{'non'})"; Expected = "Audit succès activé + ligne de commande capturée" }
    } `
    -Remediation "auditpol /set /subcategory:`"{0CCE922B-69AE-11D9-BED3-505054503030}`" /success:enable ; puis activer la capture de la ligne de commande via GPO (ci-dessous) ou : reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f" `
    -GpoPath "Computer Configuration > Stratégies d'audit avancées > Suivi détaillé > Auditer la création du processus ; + Modèles d'administration > Système > Audit du processus > Inclure la ligne de commande"

Add-Check -Id 'AUD-06' -Category 'Audit et journalisation' -Name "Audit avancé : Ouverture de session (4624/4625)" `
    -Criticality 'Moyenne' `
    -Description "Les ouvertures et échecs d'ouverture de session (4624/4625) doivent être audités pour repérer bruteforce et connexions suspectes." `
    -Test {
        $out = auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" 2>$null   # Logon (GUID)
        $text = ($out -join ' ')
        $pass = ($text -match 'Succès et échec' -or $text -match 'Success and Failure')
        @{ Pass = $pass; Current = $text.Trim(); Expected = "Succès et échec activés" }
    } `
    -Remediation "auditpol /set /subcategory:`"{0CCE9215-69AE-11D9-BED3-505054503030}`" /success:enable /failure:enable" `
    -GpoPath "Computer Configuration > Stratégies d'audit avancées > Ouverture/fermeture de session > Auditer l'ouverture de session"

Add-Check -Id 'AUD-07' -Category 'Audit et journalisation' -Name "Audit avancé : Gestion des comptes utilisateur (4720/4726)" `
    -Criticality 'Moyenne' `
    -Description "Les créations, activations et suppressions de comptes utilisateur (4720/4722/4725/4726) doivent être auditées." `
    -Test {
        $out = auditpol /get /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" 2>$null   # User Account Management (GUID)
        $text = ($out -join ' ')
        $pass = ($text -match 'Succès' -or $text -match 'Success')
        @{ Pass = $pass; Current = $text.Trim(); Expected = "Succès (a minima) activé" }
    } `
    -Remediation "auditpol /set /subcategory:`"{0CCE9235-69AE-11D9-BED3-505054503030}`" /success:enable /failure:enable" `
    -GpoPath "Computer Configuration > Stratégies d'audit avancées > Gestion des comptes > Auditer la gestion des comptes d'utilisateur"

# ============================================================================
#  CATÉGORIE 6 : RÉSEAU ET SERVICES
# ============================================================================

Add-Check -Id 'NET-01' -Category 'Réseau et services' -Name 'Pare-feu Windows activé (tous profils)' `
    -Criticality 'Élevée' `
    -Description "Le pare-feu Windows doit être actif sur les 3 profils (Domaine, Privé, Public)." `
    -Test {
        $profiles = Get-NetFirewallProfile
        $off = $profiles | Where-Object { -not $_.Enabled }
        @{ Pass = ($off.Count -eq 0); Current = "$($off.Count) profil(s) désactivé(s)"; Expected = "0 profil désactivé" }
    } `
    -Remediation "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True" `
    -GpoPath "Computer Configuration > Modèles d'administration > Réseau > Connexions réseau > Pare-feu Windows Defender"

Add-Check -Id 'NET-02' -Category 'Réseau et services' -Name 'RDP : authentification niveau réseau (NLA) activée' `
    -Criticality 'Élevée' `
    -Description "L'authentification au niveau du réseau (NLA) doit être exigée pour les connexions RDP." `
    -Test {
        $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Default 0
        @{ Pass = ($v -eq 1); Current = $v; Expected = "1" }
    } `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord" `
    -GpoPath "Configuration ordinateur > Modèles d'administration > Composants Windows > Services Bureau à distance > Sécurité > Exiger NLA"

Add-Check -Id 'NET-03' -Category 'Réseau et services' -Name 'WinRM : écouteur HTTPS configuré' `
    -Criticality 'Moyenne' `
    -Description "PowerShell Remoting devrait utiliser un écouteur HTTPS chiffré plutôt que HTTP en clair." `
    -Test {
        $listeners = winrm enumerate winrm/config/Listener 2>$null
        $text = ($listeners -join ' ')
        $pass = ($text -match 'Transport = HTTPS')
        @{ Pass = $pass; Current = $(if ($pass) { "Écouteur HTTPS présent" } else { "Aucun écouteur HTTPS détecté" }); Expected = "Au moins un écouteur HTTPS" }
    } `
    -Remediation "New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint <thumbprint_certificat> -Force" `
    -GpoPath "N/A (configuration WinRM locale ou via GPP)"

Add-Check -Id 'NET-04' -Category 'Réseau et services' -Name 'Source de temps NTP fiable configurée (PDC Emulator)' `
    -Criticality 'Moyenne' `
    -Description "Le rôle PDC Emulator doit être synchronisé sur une source de temps externe fiable (dérive d'horloge = échec Kerberos)." `
    -Test {
        $cfg = w32tm /query /configuration 2>$null
        $text = ($cfg -join ' ')
        $pass = ($text -notmatch 'NtpClient \(Local\)' -and $text -match 'NtpServer')
        @{ Pass = $pass; Current = $(if ($pass) { "Source NTP externe configurée" } else { "Horloge locale / non configurée" }); Expected = "Source NTP externe fiable" }
    } `
    -Remediation "w32tm /config /manualpeerlist:`"0.fr.pool.ntp.org,0x8 1.fr.pool.ntp.org,0x8`" /syncfromflags:manual /reliable:yes /update ; Restart-Service w32time" `
    -GpoPath "N/A (à exécuter uniquement sur le DC titulaire du rôle PDC Emulator)"

Add-Check -Id 'NET-05' -Category 'Réseau et services' -Name "Mises à jour DNS dynamiques non sécurisées désactivées" `
    -Criticality 'Élevée' `
    -Description "Les zones DNS intégrées à AD ne doivent accepter que des mises à jour dynamiques sécurisées, jamais 'Non sécurisées et sécurisées'." `
    -Test {
        if (-not $DnsModuleOK) { throw "Module DnsServer indisponible" }
        $zones = Get-DnsServerZone | Where-Object { $_.IsDsIntegrated -eq $true -and $_.ZoneType -eq 'Primary' }
        $insecure = $zones | Where-Object { $_.DynamicUpdate -eq 'NonsecureAndSecure' }
        @{ Pass = ($insecure.Count -eq 0); Current = "$($insecure.Count) zone(s) en mode non sécurisé"; Expected = "0 zone en 'NonsecureAndSecure'" }
    } `
    -Remediation "Set-DnsServerPrimaryZone -Name <zone> -DynamicUpdate Secure" `
    -GpoPath "N/A (configuration par zone DNS, console DNS ou PowerShell)"

# ============================================================================
#  CATÉGORIE 7 : NIVEAU FONCTIONNEL ET INFRASTRUCTURE
# ============================================================================

Add-Check -Id 'INF-01' -Category 'Infrastructure AD' -Name 'Niveau fonctionnel du domaine à jour' `
    -Criticality 'Faible' `
    -Description "Un niveau fonctionnel de domaine récent (2016+) apporte des protections de sécurité supplémentaires (ex. protections Kerberos avancées)." `
    -Test {
        if (-not $ADModuleOK) { throw "Module AD indisponible" }
        $dom = Get-ADDomain
        $level = $dom.DomainMode.ToString()
        $pass = ($level -match '2016|2019|2025')
        @{ Pass = $pass; Current = $level; Expected = "Windows2016Domain ou supérieur" }
    } `
    -Remediation "Vérifier que tous les DC sont sur un OS suffisamment récent, puis : Set-ADDomainMode -Identity (Get-ADDomain).DistinguishedName -DomainMode Windows2016Domain (irréversible, à planifier)" `
    -GpoPath "N/A (élévation de niveau fonctionnel, opération planifiée)"

Add-Check -Id 'INF-02' -Category 'Infrastructure AD' -Name "Stratégie de contrôleurs de domaine non désactivée" `
    -Criticality 'Critique' `
    -Description "La GPO 'Default Domain Controllers Policy' doit rester liée et activée sur l'OU Domain Controllers." `
    -Test {
        if (-not $GPModuleOK) { throw "Module GroupPolicy indisponible" }
        $gpo = Get-GPO -Name "Default Domain Controllers Policy" -ErrorAction Stop
        $links = (Get-ADOrganizationalUnit -Filter "Name -eq 'Domain Controllers'" -ErrorAction SilentlyContinue).LinkedGroupPolicyObjects
        $linked = $links -match [regex]::Escape($gpo.Id.ToString())
        @{ Pass = ([bool]$linked); Current = $(if ($linked) { "Liée" } else { "Non liée détectée" }); Expected = "Liée à l'OU Domain Controllers" }
    } `
    -Remediation "New-GPLink -Name 'Default Domain Controllers Policy' -Target (Get-ADOrganizationalUnit -Filter `"Name -eq 'Domain Controllers'`").DistinguishedName" `
    -GpoPath "gpmc.msc > vérifier le lien sur l'OU Domain Controllers"

Add-Check -Id 'INF-03' -Category 'Infrastructure AD' -Name "Permissions SYSVOL/NETLOGON restreintes" `
    -Criticality 'Moyenne' `
    -Description "Les partages SYSVOL et NETLOGON ne doivent pas être accessibles en écriture par des utilisateurs standards." `
    -Test {
        $path = "$env:SystemRoot\SYSVOL\sysvol"
        if (-not (Test-Path $path)) { throw "Chemin SYSVOL introuvable" }
        $acl = Get-Acl $path
        $badWrite = $acl.Access | Where-Object {
            $_.IdentityReference -match 'Everyone|Utilisateurs authentifiés|Authenticated Users' -and
            $_.FileSystemRights -match 'Write|FullControl|Modify'
        }
        @{ Pass = ($badWrite.Count -eq 0); Current = "$($badWrite.Count) ACE(s) d'écriture large trouvée(s)"; Expected = "0 ACE d'écriture pour Everyone/Utilisateurs authentifiés" }
    } `
    -Remediation "Auditer l'ACL avec (Get-Acl 'C:\Windows\SYSVOL\sysvol').Access, retirer les droits d'écriture excessifs via icacls ou Set-Acl, en respectant l'héritage AGDLP." `
    -GpoPath "N/A (permissions NTFS/partage sur le système de fichiers)"

# ============================================================================
#  CATÉGORIE 8 : DURCISSEMENT SYSTÈME ET ENDPOINT
# ============================================================================

Add-Check -Id 'SYS-01' -Category 'Durcissement système & endpoint' -Name 'LSA Protection (RunAsPPL) activée' `
    -Criticality 'Élevée' `
    -Description "LSASS doit s'exécuter en processus protégé (RunAsPPL) pour empêcher l'extraction de credentials/tickets par des outils type Mimikatz." `
    -Test {
        $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Default 0
        @{ Pass = ($v -eq 1 -or $v -eq 2); Current = "RunAsPPL = $v"; Expected = "1 (protégé) ou 2 (protégé sans verrou UEFI)" }
    } `
    -Remediation "reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f  puis redémarrer. Vérifier au préalable la compatibilité des pilotes/plugins LSA (SSP tiers)." `
    -GpoPath "Computer Configuration > Modèles d'administration > Système > Autorité de sécurité locale (LSA) > Configurer LSASS pour s'exécuter en tant que processus protégé"

Add-Check -Id 'SYS-02' -Category 'Durcissement système & endpoint' -Name 'Protection temps réel Microsoft Defender' `
    -Criticality 'Élevée' `
    -Description "La protection antivirus temps réel de Microsoft Defender doit être active (sauf EDR tiers équivalent documenté)." `
    -Test {
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            @{ Pass = [bool]$mp.RealTimeProtectionEnabled; Current = "Temps réel : $(if($mp.RealTimeProtectionEnabled){'activé'}else{'désactivé'}) | Antivirus : $(if($mp.AntivirusEnabled){'actif'}else{'inactif'})"; Expected = "Protection temps réel activée" }
        } catch {
            @{ Pass = $false; Current = "Get-MpComputerStatus indisponible (Defender absent ou remplacé par un EDR tiers ?)"; Expected = "Protection temps réel activée" }
        }
    } `
    -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false ; Update-MpSignature. Si un EDR/antivirus tiers assure la protection, documenter l'exception." `
    -GpoPath "Computer Configuration > Modèles d'administration > Composants Windows > Antivirus Microsoft Defender > Protection en temps réel"

Add-Check -Id 'SYS-03' -Category 'Durcissement système & endpoint' -Name 'AppLocker : contrôle applicatif actif' `
    -Criticality 'Moyenne' `
    -Description "Une stratégie AppLocker (liste blanche d'exécution) doit être définie et le service Application Identity (AppIDSvc) démarré." `
    -Test {
        try {
            $svc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
            $pol = Get-AppLockerPolicy -Effective -ErrorAction Stop
            $hasRules = @($pol.RuleCollections | Where-Object { $_.Count -gt 0 }).Count -gt 0
            @{ Pass = $hasRules; Current = "Règles AppLocker : $(if($hasRules){'présentes'}else{'aucune'}) | AppIDSvc : $(if($svc){$svc.Status}else{'absent'})"; Expected = "Stratégie AppLocker définie + AppIDSvc démarré" }
        } catch {
            @{ Pass = $false; Current = "Aucune stratégie AppLocker exploitable"; Expected = "Stratégie AppLocker définie" }
        }
    } `
    -Remediation "Définir une stratégie AppLocker (règles par défaut + règles éditeur) via GPO, démarrer AppIDSvc (Set-Service AppIDSvc -StartupType Automatic ; Start-Service AppIDSvc), commencer en mode Audit 2 à 4 semaines avant Enforce. Alternative haute sécurité : WDAC." `
    -GpoPath "Computer Configuration > Paramètres Windows > Paramètres de sécurité > Stratégies de contrôle de l'application > AppLocker"

Add-Check -Id 'SYS-04' -Category 'Durcissement système & endpoint' -Name 'Services superflus désactivés' `
    -Criticality 'Moyenne' `
    -Description "Les services non nécessaires au rôle du serveur (registre distant, WebClient, découverte réseau...) doivent être arrêtés/désactivés pour réduire la surface d'attaque." `
    -Test {
        $cibles = 'RemoteRegistry','WebClient','SSDPSRV','upnphost','lltdsvc','Browser'
        $actifs = foreach ($n in $cibles) {
            $s = Get-Service -Name $n -ErrorAction SilentlyContinue
            if ($s -and $s.Status -eq 'Running') { $n }
        }
        $actifs = @($actifs)
        @{ Pass = ($actifs.Count -eq 0); Current = $(if ($actifs.Count -eq 0) { "Aucun service superflu en cours d'exécution" } else { "En cours d'exécution : $($actifs -join ', ')" }); Expected = "Services superflus arrêtés/désactivés" }
    } `
    -Remediation "Pour chaque service superflu : Stop-Service <nom> ; Set-Service <nom> -StartupType Disabled  (ou sc config <nom> start= disabled). Toujours valider selon le rôle réel du serveur et documenter le rollback." `
    -GpoPath "N/A (services locaux ; standardiser via GPO Préférences ou baseline SCT)"

Add-Check -Id 'SYS-05' -Category 'Durcissement système & endpoint' -Name 'Mises à jour pilotées (WSUS / Windows Update)' `
    -Criticality 'Élevée' `
    -Description "Le serveur doit recevoir les mises à jour de sécurité : WSUS d'entreprise ou mises à jour automatiques pilotées par GPO." `
    -Test {
        $wu = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'WUServer' -Default $null
        $noAuto = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Default $null
        $pass = ($null -ne $wu) -or ($noAuto -eq 0)
        @{ Pass = [bool]$pass; Current = $(if ($wu) { "WSUS : $wu" } elseif ($noAuto -eq 0) { "Mises à jour automatiques activées (sans WSUS)" } else { "Aucune stratégie de mise à jour détectée" }); Expected = "WSUS configuré ou MàJ auto pilotées par GPO" }
    } `
    -Remediation "Configurer WSUS via GPO (Composants Windows > Windows Update > Spécifier l'emplacement du service de mise à jour Microsoft intranet) ou activer les mises à jour automatiques ; compléter par un suivi des correctifs." `
    -GpoPath "Computer Configuration > Modèles d'administration > Composants Windows > Windows Update"

Add-Check -Id 'SYS-06' -Category 'Durcissement système & endpoint' -Name 'Chiffrement BitLocker du volume système' `
    -Criticality 'Faible' `
    -Description "Le volume système devrait être chiffré (BitLocker) pour protéger les données au repos en cas de vol/accès physique. Pertinence variable pour un DC en datacenter physiquement sécurisé." `
    -Test {
        try {
            $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
            @{ Pass = ($vol.ProtectionStatus -eq 'On'); Current = "$($env:SystemDrive) : ProtectionStatus=$($vol.ProtectionStatus) ($($vol.VolumeStatus))"; Expected = "ProtectionStatus = On" }
        } catch {
            @{ Pass = $false; Current = "BitLocker non disponible / fonctionnalité non installée"; Expected = "ProtectionStatus = On" }
        }
    } `
    -Remediation "Install-WindowsFeature BitLocker -IncludeManagementTools ; puis Enable-BitLocker -MountPoint `$env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector ; sauvegarder la clé de récupération dans l'AD (Backup-BitLockerKeyProtector)." `
    -GpoPath "Computer Configuration > Modèles d'administration > Composants Windows > Chiffrement de lecteur BitLocker"

# ============================================================================
#  CALCUL DU SCORE
# ============================================================================

$scoreMax = 0
$scoreObtenu = 0
$summary = @{ 'Critique' = @{Total=0;Fail=0}; 'Élevée' = @{Total=0;Fail=0}; 'Moyenne' = @{Total=0;Fail=0}; 'Faible' = @{Total=0;Fail=0} }

foreach ($r in $Global:Results) {
    $w = $Weights[$r.Criticality]
    if ($r.Status -ne 'Erreur') {
        $scoreMax += $w
        if ($r.Status -eq 'Conforme') { $scoreObtenu += $w }
    }
    $summary[$r.Criticality].Total++
    if ($r.Status -eq 'Non conforme') { $summary[$r.Criticality].Fail++ }
}

$scorePct = if ($scoreMax -gt 0) { [math]::Round(($scoreObtenu / $scoreMax) * 100, 1) } else { 0 }

$grade = switch ($scorePct) {
    { $_ -ge 90 } { 'A - Excellent'; break }
    { $_ -ge 75 } { 'B - Bon'; break }
    { $_ -ge 60 } { 'C - Moyen'; break }
    { $_ -ge 40 } { 'D - Insuffisant'; break }
    default       { 'F - Critique' }
}

$gradeColor = switch ($scorePct) {
    { $_ -ge 90 } { '#22c55e'; break }
    { $_ -ge 75 } { '#84cc16'; break }
    { $_ -ge 60 } { '#eab308'; break }
    { $_ -ge 40 } { '#f97316'; break }
    default       { '#ef4444' }
}

Write-Host "`nScore de durcissement : $scorePct% ($grade)`n" -ForegroundColor Cyan
foreach ($crit in @('Critique','Élevée','Moyenne','Faible')) {
    $s = $summary[$crit]
    Write-Host ("  {0,-10} : {1} non conforme(s) / {2} contrôle(s)" -f $crit, $s.Fail, $s.Total)
}

# ============================================================================
#  GÉNÉRATION DU RAPPORT HTML
# ============================================================================

function Get-StatusBadge($status) {
    switch ($status) {
        'Conforme'      { return '<span class="badge badge-ok">✅ Conforme</span>' }
        'Non conforme'  { return '<span class="badge badge-fail">❌ Non conforme</span>' }
        default         { return '<span class="badge badge-error">⚠️ Erreur / non vérifié</span>' }
    }
}

function Get-CritBadge($crit) {
    $cls = switch ($crit) {
        'Critique' { 'crit-critique' }
        'Élevée'   { 'crit-elevee' }
        'Moyenne'  { 'crit-moyenne' }
        'Faible'   { 'crit-faible' }
    }
    return "<span class=`"badge $cls`">$crit</span>"
}

$reportDate = $ScriptStart.ToString('dd/MM/yyyy HH:mm:ss')
$categories = $Global:Results | Select-Object -ExpandProperty Category -Unique

$rowsHtml = New-Object System.Text.StringBuilder
foreach ($cat in $categories) {
    [void]$rowsHtml.Append("<tr class='cat-row'><td colspan='4'>$cat</td></tr>")
    foreach ($r in ($Global:Results | Where-Object { $_.Category -eq $cat } | Sort-Object { @{'Critique'=0;'Élevée'=1;'Moyenne'=2;'Faible'=3}[$_.Criticality] })) {
        $remBlock = ""
        if ($r.Status -ne 'Conforme') {
            $errLine = if ($r.Error) { "<div class='errline'>Erreur technique : $($r.Error)</div>" } else { "" }
            $remBlock = @"
<div class='remediation'>
  <div><strong>Valeur actuelle :</strong> $($r.Current) &nbsp;|&nbsp; <strong>Attendu :</strong> $($r.Expected)</div>
  <div class='remcode'><strong>Correction :</strong> <code>$($r.Remediation)</code></div>
  <div class='gpo'><strong>Chemin GPO :</strong> $($r.GpoPath)</div>
  $errLine
</div>
"@
        }
        [void]$rowsHtml.Append(@"
<tr>
  <td class='idcol'>$($r.Id)</td>
  <td>
    <div class='checkname'>$($r.Name)</div>
    <div class='checkdesc'>$($r.Description)</div>
    $remBlock
  </td>
  <td>$(Get-CritBadge $r.Criticality)</td>
  <td>$(Get-StatusBadge $r.Status)</td>
</tr>
"@)
    }
}

$summaryCardsHtml = ($summary.GetEnumerator() | Sort-Object { @{'Critique'=0;'Élevée'=1;'Moyenne'=2;'Faible'=3}[$_.Key] } | ForEach-Object {
    $k = $_.Key; $v = $_.Value
    $cls = switch ($k) { 'Critique' {'crit-critique'} 'Élevée' {'crit-elevee'} 'Moyenne' {'crit-moyenne'} 'Faible' {'crit-faible'} }
    "<div class='sumcard'><div class='badge $cls'>$k</div><div class='sumnum'>$($v.Fail) / $($v.Total)</div><div class='sumlabel'>non conformes</div></div>"
}) -join "`n"

$html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport d'audit de durcissement - $env:COMPUTERNAME</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #1e293b; margin: 0; padding: 0; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 32px 20px 60px; }
  header { background: linear-gradient(135deg, #1e293b, #334155); color: #fff; padding: 32px; border-radius: 12px; margin-bottom: 24px; }
  header h1 { margin: 0 0 6px; font-size: 24px; }
  header .meta { color: #cbd5e1; font-size: 14px; }
  .scorebox { display: flex; align-items: center; gap: 28px; background: #fff; border-radius: 12px; padding: 24px 28px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
  .scorecircle { width: 120px; height: 120px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 28px; font-weight: 700; color: #fff; flex-shrink: 0; }
  .scoreinfo .gradeline { font-size: 20px; font-weight: 600; margin-bottom: 4px; }
  .scoreinfo .sub { color: #64748b; font-size: 14px; }
  .summarygrid { display: flex; gap: 14px; margin-bottom: 24px; flex-wrap: wrap; }
  .sumcard { background: #fff; border-radius: 10px; padding: 16px 20px; flex: 1; min-width: 140px; box-shadow: 0 1px 3px rgba(0,0,0,.08); text-align: center; }
  .sumnum { font-size: 26px; font-weight: 700; margin-top: 8px; }
  .sumlabel { font-size: 12px; color: #64748b; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  thead th { background: #1e293b; color: #fff; text-align: left; padding: 12px 14px; font-size: 13px; text-transform: uppercase; letter-spacing: .03em; }
  tbody td { padding: 14px; border-bottom: 1px solid #e2e8f0; vertical-align: top; font-size: 14px; }
  tr.cat-row td { background: #f1f5f9; font-weight: 700; color: #334155; font-size: 13px; text-transform: uppercase; letter-spacing: .04em; padding: 10px 14px; }
  .idcol { font-family: Consolas, monospace; color: #64748b; white-space: nowrap; font-size: 12px; }
  .checkname { font-weight: 600; margin-bottom: 4px; }
  .checkdesc { color: #64748b; font-size: 13px; margin-bottom: 6px; }
  .remediation { background: #fef2f2; border-left: 3px solid #ef4444; border-radius: 6px; padding: 10px 12px; margin-top: 8px; font-size: 12.5px; }
  .remediation .remcode { margin-top: 6px; }
  .remediation code { background: #1e293b; color: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-size: 12px; word-break: break-word; }
  .remediation .gpo { margin-top: 6px; color: #475569; }
  .errline { margin-top: 6px; color: #b45309; font-style: italic; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; white-space: nowrap; }
  .badge-ok { background: #dcfce7; color: #166534; }
  .badge-fail { background: #fee2e2; color: #991b1b; }
  .badge-error { background: #fef3c7; color: #92400e; }
  .crit-critique { background: #7f1d1d; color: #fff; }
  .crit-elevee { background: #ea580c; color: #fff; }
  .crit-moyenne { background: #ca8a04; color: #fff; }
  .crit-faible { background: #64748b; color: #fff; }
  footer { text-align: center; color: #94a3b8; font-size: 12px; margin-top: 30px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>🛡️ Rapport d'audit de durcissement — Contrôleur de domaine</h1>
    <div class="meta">Hôte : $env:COMPUTERNAME &nbsp;|&nbsp; Généré le $reportDate</div>
  </header>

  <div class="scorebox">
    <div class="scorecircle" style="background:$gradeColor;">$scorePct%</div>
    <div class="scoreinfo">
      <div class="gradeline">Niveau : $grade</div>
      <div class="sub">$scoreObtenu / $scoreMax points pondérés obtenus (pondération par criticité : Critique=10, Élevée=6, Moyenne=3, Faible=1)</div>
    </div>
  </div>

  <div class="summarygrid">
    $summaryCardsHtml
  </div>

  <table>
    <thead>
      <tr><th style="width:80px;">ID</th><th>Contrôle</th><th style="width:110px;">Criticité</th><th style="width:150px;">Statut</th></tr>
    </thead>
    <tbody>
      $($rowsHtml.ToString())
    </tbody>
  </table>

  <footer>Outil d'audit généré à des fins pédagogiques — à valider/adapter selon votre contexte de production avant application des corrections.</footer>
</div>
</body>
</html>
"@

$reportFile = Join-Path $OutputPath "AuditDC_$($env:COMPUTERNAME)_$($ScriptStart.ToString('yyyyMMdd_HHmmss')).html"
$html | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "`nRapport HTML généré : $reportFile" -ForegroundColor Green

if ($OpenReport) {
    Start-Process $reportFile
}

Write-Host "`nAudit terminé. Rapport HTML généré (et ouvert dans le navigateur)." -ForegroundColor Cyan
Read-Host "Appuyez sur Entrée pour fermer cette fenêtre"
