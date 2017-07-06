# Readme (Version française)

## sflow-Graylog

Ce programme permet de convertir des logs de type sflow arrivant sur un port source en ligne de texte étant renvoyées sur un autre port de la machine.
Ainsi, il est possible d'ajouter à graylog les logs de type sflow en sélectionnant l'inputs Raw/Plaintext UDP et en écoutant le port de sortie du programme.

## installation

Télécharger le dossiers puis décompresser. Pour compiler, taper le ligne de commande :

	gcc slow5.c -o sflow-adapter

**Pour exécuter :**

	./sflow-adapter -s [port source] -d [port destination]
	
Options supplémentaires :
* -l -> affiche dans le terminal les logs décodé.
* -p -> permet de fork afin de créer un processur

**Pour debian :**

Il est possble d'utiliser le programme en daemon à l'aide du script sflow
* Placer le script dans /etc/init.d
* Editer ce sript pour spécifier les options souhaité (port source et destination par exemple)
* Modifier également le chemin d'acces au programme.

Dans le terminal saisir :
```
systemctl daemon-reload
systemctl enable sflow.service
systemctl start sflow.service
```
## source

Pour réaliser ce programme, j'ai utilisé le code disponible sur :
* http://www.inmon.com/technology/sflowVersion5.php
* https://github.com/Open-Network-Insight/spot-nfdump/blob/master/nfdump/bin/sflow.c

# Readme (English version)

## sflow-Graylog

This program allows you to convert sflow logs comming from a port of your machine into simple text lines which are send to another port. 
So, it's possible to add sflow logs into Graylog by selecting the Raw/Plaintext UDP input and listening the destination port of the program


## installation

Download this repositary and extract it. To compile, use in your terminal :

	gcc slow5.c -o sflow-adapter

**To execute :**

	./sflow-adapter -s [port source] -d [port destination]
	
Other options :
* -l -> display the logs in the terminal
* -p -> call fork to create another process

**With debian :**

It is possible to create a daemon
* Place the script ```sflow``` in /etc/init.d/
* Edit it to change your port
* Don't forget to change the path of the executable

in the terminal, use:
```
systemctl daemon-reload
systemctl enable sflow.service
systemctl start sflow.service
```
## source

To create this program, I used:
* http://www.inmon.com/technology/sflowVersion5.php
* https://github.com/Open-Network-Insight/spot-nfdump/blob/master/nfdump/bin/sflow.c
