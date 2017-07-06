# sflow-Graylog

Ce programme permet de convertir des logs de type sflow arrivant sur un port source en ligne de texte étant renvoyées sur un autre port de la machine.

# installation

Télécharger le dossiers puis décompresser. Pour compiler, taper le ligne de commande :

	gcc slow5.c -o sflow-adapter

**Pour exécuter :**

	./sflow-adapter -s [port source] -d [port destination]
	
options supplémentaires :
* -l -> affiche dans le terminal les logs décodé.
* -p -> permet de fork afin de créer un processur

**Pour debian :**

Il est possble d'utiliser le programme en daemon à l'aide du script sflow
* Placer le script dans /etc/init.d
* Editer ce sript pour spécifier les options souhaité (port source et destination par exemple)
* Modifier également le chemin d'acces au script.

Dans le terminal saisir :
```
systemctl daemon-reload
systemctl enable sflow.service
systemctl start sflow.service
```
# source

Pour réaliser ce programme, j'ai utilisé le code disponible sur :
* http://www.inmon.com/technology/sflowVersion5.php
* https://github.com/Open-Network-Insight/spot-nfdump/blob/master/nfdump/bin/sflow.c
