# Readme (Version française)

## sflow-Graylog

Ce programme permet de convertir des logs de type sflow arrivant sur un port source d'une machine, en ligne de texte qui sont ensuite renvoyées sur un autre port de cette même machine.
Ainsi, il est possible d'ajouter à Graylog les logs de type sflow en sélectionnant dans l'application l'input Raw/Plaintext UDP et en écoutant le port de sortie configuré dans le programme sflow-adapter.

## installation

Télécharger le dossier puis le décompresser. Pour compiler, taper la ligne de commande suivante :

	gcc slow5.c -o sflow-adapter

**Pour exécuter :**

	./sflow-adapter -s [port source] -d [port destination]
	
Options supplémentaires :
* -l -> affiche dans le terminal les logs décodé.
* -p -> permet de forker afin de créer un processus

**Pour debian :**

Il est possble d'exécuter le programme en daemon à l'aide du script sflow
* Placer le script dans /etc/init.d
* Éditer ce script pour spécifier les options souhaitées (port source et port de destination par exemple)
* Modifier également le chemin d'accès au programme.

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

This program allows you to convert sflow logs comming from a source port of your computer into raw text lines which are sent to a destination port of the same machine. 
So, it's possible to add sflow logs into Graylog by selecting the Raw/Plaintext UDP input and listening the destination port configured in the sflow-adapter program.


## installation

Download this repositary and extract it. To compile, type the following command in a terminal :

	gcc slow5.c -o sflow-adapter

**To execute :**

	./sflow-adapter -s [port source] -d [port destination]
	
More options :
* -l -> display the decoded logs in the terminal
* -p -> call fork function to create another process

**With debian :**

It is possible to create a daemon with the ```sflow``` script :
* Copy the script ```sflow``` in /etc/init.d/
* Edit this script to configure your port
* Don't forget to configure the correct the path of the executable file

In a terminal window, use:
```
systemctl daemon-reload
systemctl enable sflow.service
systemctl start sflow.service
```
## source

To create this program, I used:
* http://www.inmon.com/technology/sflowVersion5.php
* https://github.com/Open-Network-Insight/spot-nfdump/blob/master/nfdump/bin/sflow.c
