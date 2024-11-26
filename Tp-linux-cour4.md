# TP Avancé : "Mission Ultime : Sauvegarde et Sécurisation"

## Contexte
Votre serveur critique est opérationnel, mais de nombreuses failles subsistent. Votre objectif est d'identifier les faiblesses, de sécuriser les données et d’automatiser les surveillances pour garantir un fonctionnement sûr à long terme.

---

## Objectifs
1. Surveiller les répertoires critiques pour détecter des modifications suspectes.
2. Identifier et éliminer des tâches malveillantes laissées par des attaquants.
3. Réorganiser les données pour optimiser l’espace disque avec LVM.
4. Automatiser les sauvegardes et surveillances avec des scripts robustes.
5. Configurer un pare-feu pour protéger les services actifs.

---

## Étape 1 : Analyse et nettoyage du serveur

1. **Lister les tâches cron pour détecter des backdoors** :
```
[root@vbox ~]# for user in $(cut -f1 -d: /etc/passwd); do echo -e "\nUtilisateur:\x1b[32;01m $user \x1b[39;49;00m"; crontab -u $user -l; done

Utilisateur: root 
no crontab for root

.....

Utilisateur: attacker 
*/10 * * * * /tmp/.hidden_script
```

2. **Identifier et supprimer les fichiers cachés** :
```
[root@vbox ~]# ls -a /tmp; ls -a /var/tmp; ls -a /home
.
..
.ICE-unix
.X11-unix
.XIM-unix
.font-unix
.hidden_file
.hidden_script
malicious.sh
systemd-private-597802a28e0a4d0c9ce15d640a806525-chronyd.service-d0MIJx
systemd-private-597802a28e0a4d0c9ce15d640a806525-dbus-broker.service-pAp3nm
systemd-private-597802a28e0a4d0c9ce15d640a806525-irqbalance.service-LZlfVM
systemd-private-597802a28e0a4d0c9ce15d640a806525-kdump.service-lmPJmW
systemd-private-597802a28e0a4d0c9ce15d640a806525-systemd-logind.service-KsXNnK
.
..
.nop
systemd-private-597802a28e0a4d0c9ce15d640a806525-chronyd.service-AxMytj
systemd-private-597802a28e0a4d0c9ce15d640a806525-dbus-broker.service-BuN4cL
systemd-private-597802a28e0a4d0c9ce15d640a806525-irqbalance.service-nWZLXf
systemd-private-597802a28e0a4d0c9ce15d640a806525-kdump.service-W0fERR
systemd-private-597802a28e0a4d0c9ce15d640a806525-systemd-logind.service-gtODxY
.  ..  attacker  hidden_data
[root@vbox ~]# cat /var/tmp/.nop
héhé
[root@vbox ~]# rm /tmp/.h*; rm /tmp/malicious.sh; rm /var/tmp/.nop; rm -r /home/attacker/
rm: remove regular file '/tmp/.hidden_file'? y
rm: remove regular file '/tmp/.hidden_script'? y
rm: remove regular file '/tmp/malicious.sh'? y
rm: remove regular file '/var/tmp/.nop'? y
rm: descend into directory '/home/attacker/'? y
rm: remove regular file '/home/attacker/.bash_profile'? y
rm: remove regular file '/home/attacker/.bashrc'? y
rm: remove regular file '/home/attacker/.bash_logout'? y
rm: remove regular file '/home/attacker/.bash_history'? y
rm: remove regular file '/home/attacker/.hidden_file'? y
rm: remove directory '/home/attacker/'? y
```

3. **Analyser les connexions réseau actives** :
   - Listez les connexions actives pour repérer d'éventuelles communications malveillantes.
```
root@vbox ~]# netstat
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0    164 vbox:ssh                georges-laptop:47688    ESTABLISHED
tcp        0      0 vbox:58216              ccpntc11.in2p3.fr:http  TIME_WAIT  
tcp        0      0 vbox:58224              ccpntc11.in2p3.fr:http  TIME_WAIT  
tcp        0      0 vbox:58206              ccpntc11.in2p3.fr:http  TIME_WAIT  
udp        0      0 vbox:bootpc             _gateway:bootps         ESTABLISHED
Active UNIX domain sockets (w/o servers)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ]         DGRAM                    17939    /run/user/0/systemd/notify
unix  3      [ ]         DGRAM      CONNECTED     99       /run/systemd/notify
unix  9      [ ]         DGRAM      CONNECTED     112      /run/systemd/journal/dev-log
unix  7      [ ]         DGRAM      CONNECTED     114      /run/systemd/journal/socket
unix  2      [ ]         DGRAM      CONNECTED     18673    /run/chrony/chronyd.sock
unix  3      [ ]         STREAM     CONNECTED     18799    
unix  3      [ ]         STREAM     CONNECTED     810      /run/systemd/journal/stdout
unix  3      [ ]         DGRAM      CONNECTED     100      
unix  3      [ ]         STREAM     CONNECTED     17852    
unix  3      [ ]         STREAM     CONNECTED     18689    
unix  3      [ ]         STREAM     CONNECTED     18861    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     18651    
unix  3      [ ]         STREAM     CONNECTED     17887    
unix  3      [ ]         STREAM     CONNECTED     18629    
unix  3      [ ]         STREAM     CONNECTED     17616    
unix  3      [ ]         STREAM     CONNECTED     928      /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     769      /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     18637    
unix  3      [ ]         STREAM     CONNECTED     19656    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     18649    
unix  2      [ ]         DGRAM      CONNECTED     19985    
unix  3      [ ]         STREAM     CONNECTED     821      /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     17944    
unix  3      [ ]         STREAM     CONNECTED     776      /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     18628    
unix  3      [ ]         STREAM     CONNECTED     18798    
unix  3      [ ]         STREAM     CONNECTED     17700    
unix  3      [ ]         STREAM     CONNECTED     765      /run/systemd/journal/stdout
unix  3      [ ]         DGRAM      CONNECTED     101      
unix  3      [ ]         STREAM     CONNECTED     18650    
unix  3      [ ]         DGRAM      CONNECTED     16775    
unix  2      [ ]         DGRAM      CONNECTED     17922    
unix  3      [ ]         STREAM     CONNECTED     18679    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     778      
unix  3      [ ]         STREAM     CONNECTED     912      /run/systemd/journal/stdout
unix  3      [ ]         DGRAM      CONNECTED     16577    
unix  3      [ ]         STREAM     CONNECTED     18725    /run/dbus/system_bus_socket
unix  2      [ ]         DGRAM                    18688    
unix  3      [ ]         STREAM     CONNECTED     808      
unix  2      [ ]         DGRAM      CONNECTED     17676    
unix  3      [ ]         STREAM     CONNECTED     771      /run/dbus/system_bus_socket
unix  3      [ ]         DGRAM      CONNECTED     16774    
unix  3      [ ]         STREAM     CONNECTED     784      /run/systemd/journal/stdout
unix  2      [ ]         DGRAM      CONNECTED     18745    
unix  2      [ ]         DGRAM      CONNECTED     16573    
unix  3      [ ]         STREAM     CONNECTED     16807    
unix  3      [ ]         STREAM     CONNECTED     584      /run/systemd/journal/stdout
unix  2      [ ]         DGRAM      CONNECTED     1897     
unix  3      [ ]         DGRAM      CONNECTED     16578    
unix  2      [ ]         DGRAM      CONNECTED     18664    
unix  3      [ ]         STREAM     CONNECTED     18683    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     16561    
unix  3      [ ]         STREAM     CONNECTED     847      
unix  3      [ ]         DGRAM      CONNECTED     17940    
unix  2      [ ]         DGRAM      CONNECTED     18647    
unix  2      [ ]         STREAM     CONNECTED     19926    
unix  3      [ ]         DGRAM      CONNECTED     17941    
unix  3      [ ]         STREAM     CONNECTED     16762    
unix  2      [ ]         DGRAM      CONNECTED     18627    
unix  2      [ ]         DGRAM      CONNECTED     18915    
unix  2      [ ]         DGRAM      CONNECTED     2986     
unix  3      [ ]         STREAM     CONNECTED     19991    
unix  3      [ ]         STREAM     CONNECTED     19990    
unix  2      [ ]         DGRAM      CONNECTED     17932    
unix  3      [ ]         STREAM     CONNECTED     909      
Active Bluetooth connections (w/o servers)
Proto  Destination       Source            State         PSM DCID   SCID      IMTU    OMTU Security
Proto  Destination       Source            State     Channel

```
---

## Étape 2 : Configuration avancée de LVM

1. **Créer un snapshot de sécurité pour `/mnt/secure_data`** :
```
[root@vbox ~]# sudo lvcreate --size 1G --snapshot --name secure_data_snapshot /dev/vg_secure/secure_data
  Reducing COW size 1.00 GiB down to maximum usable size 504.00 MiB.
  Logical volume "secure_data_snapshot" created.
```

2. **Tester la restauration du snapshot** :
```
[root@vbox ~]# cd /mnt/secure_data/
[root@vbox secure_data]# ls
lost+found  sensitive1.txt  sensitive2.txt
[root@vbox secure_data]# rm sensitive1.txt 
rm: remove regular file 'sensitive1.txt'? y
[root@vbox secure_data]# ls
lost+found  sensitive2.txt
[root@vbox secure_data]# sudo mkdir -p /mnt/secure_data_snapshot
[root@vbox secure_data]# sudo mount /dev/vg_secure/secure_data_snapshot /mnt/secure_data_snapshot
[root@vbox secure_data]# cd ..
[root@vbox mnt]# ls
secure_data  secure_data_snapshot
[root@vbox mnt]# cd secure_data_snapshot/
[root@vbox secure_data_snapshot]# ls
lost+found  sensitive1.txt  sensitive2.txt
[root@vbox secure_data_snapshot]# sudo cp /mnt/secure_data_snapshot/sensitive1.txt /mnt/secure_data/
[root@vbox secure_data_snapshot]# cd ..
[root@vbox mnt]# cd secure_data
[root@vbox secure_data]# ls
lost+found  sensitive1.txt  sensitive2.txt
[root@vbox secure_data]# 
```


3. **Optimiser l’espace disque** :
   - Si le volume logique `secure_data` est plein, étendez-le en ajoutant de l’espace à partir du groupe de volumes existant.

---

## Étape 3 : Automatisation avec un script de sauvegarde

1. **Créer un script `secure_backup.sh`** :
```
[root@vbox secure_data]# sudo nano /usr/local/bin/secure_backup.sh
[root@vbox secure_data]# sudo chmod +x /usr/local/bin/secure_backup.sh
[root@vbox secure_data]# sudo /usr/local/bin/secure_backup.sh
[root@vbox secure_data]# sudo /usr/local/bin/secure_backup.sh
Création de l'archive secure_data_20241125.tar.gz...
Sauvegarde réussie : /backup/secure_data_20241125.tar.gz
```
```
[root@vbox secure_data]# sudo cat /usr/local/bin/secure_backup.sh
#!/bin/bash

# Définir les variables
SOURCE_DIR="/mnt/secure_data"
BACKUP_DIR="/backup"
DATE=$(date +%Y%m%d)
ARCHIVE_NAME="secure_data_$DATE.tar.gz"
EXCLUDE_PATTERNS="*.tmp *.log .*"

# Créer le dossier de sauvegarde s'il n'existe pas
if [ ! -d "$BACKUP_DIR" ]; then
  echo "Le dossier de sauvegarde n'existe pas. Création de $BACKUP_DIR..."
  mkdir -p "$BACKUP_DIR"
fi

# Créer l'archive en excluant les fichiers spécifiés
echo "Création de l'archive $ARCHIVE_NAME..."
tar --exclude="$SOURCE_DIR/*.tmp" --exclude="$SOURCE_DIR/*.log" --exclude="$SOURCE_DIR/.*" -czf "$BACKUP_DIR/$ARCHIVE_NAME" -C "$SOURCE_DIR" .

# Vérifier si la sauvegarde a réussi
if [ $? -eq 0 ]; then
  echo "Sauvegarde réussie : $BACKUP_DIR/$ARCHIVE_NAME"
else
  echo "Erreur lors de la création de la sauvegarde."
  exit 1
fi

exit 0

```

2. **Ajoutez une fonction de rotation des sauvegardes** :
```
[root@vbox secure_data]# cat /usr/local/bin/secure_backup.sh
#!/bin/bash

# Définir les variables
SOURCE_DIR="/mnt/secure_data"
BACKUP_DIR="/backup"
DATE=$(date +%Y%m%d)
ARCHIVE_NAME="secure_data_$DATE.tar.gz"
EXCLUDE_PATTERNS="*.tmp *.log .*"
MAX_BACKUPS=7

# Fonction pour effectuer la rotation des sauvegardes
rotate_backups() {
  echo "Vérification du nombre de sauvegardes existantes..."
  BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/secure_data_*.tar.gz 2>/dev/null | wc -l)

  if [ "$BACKUP_COUNT" -gt "$MAX_BACKUPS" ]; then
    echo "Plus de $MAX_BACKUPS sauvegardes détectées. Suppression des plus anciennes..."
    ls -1t "$BACKUP_DIR"/secure_data_*.tar.gz | tail -n +$(($MAX_BACKUPS + 1)) | xargs rm -f
    echo "Rotation des sauvegardes terminée."
  else
    echo "Le nombre de sauvegardes est dans la limite ($BACKUP_COUNT/$MAX_BACKUPS)."
  fi
}

# Créer le dossier de sauvegarde s'il n'existe pas
if [ ! -d "$BACKUP_DIR" ]; then
  echo "Le dossier de sauvegarde n'existe pas. Création de $BACKUP_DIR..."
  mkdir -p "$BACKUP_DIR"
fi

# Créer l'archive en excluant les fichiers spécifiés
echo "Création de l'archive $ARCHIVE_NAME..."
tar --exclude="$SOURCE_DIR/*.tmp" --exclude="$SOURCE_DIR/*.log" --exclude="$SOURCE_DIR/.*" -czf "$BACKUP_DIR/$ARCHIVE_NAME" -C "$SOURCE_DIR" .

# Vérifier si la sauvegarde a réussi
if [ $? -eq 0 ]; then
  echo "Sauvegarde réussie : $BACKUP_DIR/$ARCHIVE_NAME"
else
  echo "Erreur lors de la création de la sauvegarde."
  exit 1
fi

# Appeler la fonction de rotation des sauvegardes
rotate_backups

exit 0

```

3. **Testez le script** :
```
[root@vbox secure_data]# sudo /usr/local/bin/secure_backup.sh
Création de l'archive secure_data_20241125.tar.gz...
Sauvegarde réussie : /backup/secure_data_20241125.tar.gz
Vérification du nombre de sauvegardes existantes...
Le nombre de sauvegardes est dans la limite (1/7).
[root@vbox secure_data]# ls -lt /backup
total 4
-rw-r--r--. 1 root root 230 Nov 25 17:34 secure_data_20241125.tar.gz 

```

4. **Automatisez avec une tâche cron** :
```
[root@vbox ~]# crontab -l
0 3 * * * /usr/local/bin/secure_backup.sh
```

---

## Étape 4 : Surveillance avancée avec `auditd`

1. **Configurer auditd pour surveiller `/etc`** :
```
[root@vbox ~]# sudo auditctl -l
-w /etc -p wa -k etc_watch
```

2. **Tester la surveillance** :
```
[root@vbox ~]# sudo touch /etc/test_file
sudo echo "Modification" >> /etc/test_file
[root@vbox ~]# sudo ausearch -k etc_watch
----
time->Mon Nov 25 22:41:00 2024
type=PROCTITLE msg=audit(1732570860.526:512): proctitle=2F7362696E2F617564697463746C002D52002F6574632F61756469742F61756469742E72756C6573
type=SYSCALL msg=audit(1732570860.526:512): arch=c000003e syscall=44 success=yes exit=1072 a0=3 a1=7fffc47380d0 a2=430 a3=0 items=0 ppid=3239 pid=3259 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=5 comm="auditctl" exe="/usr/sbin/auditctl" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
type=CONFIG_CHANGE msg=audit(1732570860.526:512): auid=0 ses=5 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key="etc_watch" list=4 res=1
----
time->Mon Nov 25 22:41:32 2024
type=PROCTITLE msg=audit(1732570892.839:519): proctitle=2F7362696E2F617564697463746C002D52002F6574632F61756469742F61756469742E72756C6573
type=SOCKADDR msg=audit(1732570892.839:519): saddr=100000000000000000000000
type=SYSCALL msg=audit(1732570892.839:519): arch=c000003e syscall=44 success=yes exit=1072 a0=3 a1=7ffdf42222d0 a2=430 a3=0 items=0 ppid=3269 pid=3285 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=5 comm="auditctl" exe="/usr/sbin/auditctl" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
type=CONFIG_CHANGE msg=audit(1732570892.839:519): auid=0 ses=5 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=remove_rule key="etc_watch" list=4 res=1
----
time->Mon Nov 25 22:41:32 2024
type=PROCTITLE msg=audit(1732570892.842:523): proctitle=2F7362696E2F617564697463746C002D52002F6574632F61756469742F61756469742E72756C6573
type=SYSCALL msg=audit(1732570892.842:523): arch=c000003e syscall=44 success=yes exit=1072 a0=3 a1=7ffdf4224770 a2=430 a3=0 items=0 ppid=3269 pid=3285 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=5 comm="auditctl" exe="/usr/sbin/auditctl" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
type=CONFIG_CHANGE msg=audit(1732570892.842:523): auid=0 ses=5 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key="etc_watch" list=4 res=1
----
time->Mon Nov 25 22:45:54 2024
type=PROCTITLE msg=audit(1732571154.915:536): proctitle=746F756368002F6574632F746573745F66696C65
type=PATH msg=audit(1732571154.915:536): item=1 name="/etc/test_file" inode=21060 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1732571154.915:536): item=0 name="/etc/" inode=18 dev=fd:00 mode=040755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:etc_t:s0 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1732571154.915:536): cwd="/root"
type=SYSCALL msg=audit(1732571154.915:536): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffdaceb68f1 a2=941 a3=1b6 items=2 ppid=3313 pid=3315 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=5 comm="touch" exe="/usr/bin/touch" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="etc_watch"
----
time->Mon Nov 25 22:45:54 2024
type=PROCTITLE msg=audit(1732571154.917:539): proctitle="-bash"
type=PATH msg=audit(1732571154.917:539): item=1 name="/etc/test_file" inode=21060 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1732571154.917:539): item=0 name="/etc/" inode=18 dev=fd:00 mode=040755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:etc_t:s0 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1732571154.917:539): cwd="/root"
type=SYSCALL msg=audit(1732571154.917:539): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=55ce1abd71a0 a2=441 a3=1b6 items=2 ppid=1525 pid=3316 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=5 comm="bash" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="etc_watch"
```

3. **Analyser les événements** :
```
[root@vbox ~]# sudo ausearch -k etc_watch > /var/log/audit_etc.log
```

---

## Étape 5 : Sécurisation avec Firewalld

1. **Configurer un pare-feu pour SSH et HTTP/HTTPS uniquement** :
```
[root@vbox ~]# sudo systemctl enable --now firewalld
[root@vbox ~]# sudo firewall-cmd --get-active-zones
public
  interfaces: enp0s3 enp0s8
[root@vbox ~]# sudo firewall-cmd --zone=public --add-service=ssh --permanent; sudo firewall-cmd --zone=public --add-service=http --permanent; sudo firewall-cmd --zone=public --add-service=https --permanent
Warning: ALREADY_ENABLED: ssh
success
success
Warning: ALREADY_ENABLED: https
success
[root@vbox ~]# sudo firewall-cmd --zone=public --list-all
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources: 
  services: cockpit dhcpv6-client https ssh
  ports: 2222/tcp
  protocols: 
  forward: yes
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
[root@vbox ~]# sudo firewall-cmd --zone=public --remove-service=cockpit --permanent
success
[root@vbox ~]# sudo firewall-cmd --reload
success
```

2. **Bloquer des IP suspectes** :
   - À l’aide des logs d’audit et des connexions réseau, bloquez les adresses IP malveillantes identifiées.

3. **Restreindre SSH à un sous-réseau spécifique** :
```
[root@vbox ~]# sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="10.6.1.0/24" service name="ssh" accept' --permanent
success
[root@vbox ~]# sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" service name="ssh" reject' --permanent
success
[root@vbox ~]# sudo firewall-cmd --reload
success
```

---