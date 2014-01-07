CREATE TABLE `users` (
	  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
	  `username` varchar(50) NOT NULL,
	  `password` varchar(100) DEFAULT NULL,
	  `salt` varchar(100) DEFAULT NULL,
	  PRIMARY KEY (`id`,`username`),
	  UNIQUE KEY `id` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8

/*admin:ttadmin*/
INSERT INTO `users` (username, password, salt) VALUES ('admin', '088dd92c3730b41040d7807e677efff57166cb87','1389128617490');
