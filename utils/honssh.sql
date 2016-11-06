CREATE TABLE `auth` (
  `success` TINYINT(1) NOT NULL,
  `username` VARCHAR(100) NOT NULL,
  `password` VARCHAR(100) NOT NULL,
  `timestamp` DATETIME NOT NULL,
  PRIMARY KEY (`timestamp`, `password`, `username`, `success`)
) ;

CREATE TABLE `clients` (
  `id` INT(4) NOT NULL AUTO_INCREMENT,
  `version` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ;

CREATE TABLE `sensors` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `ip` VARCHAR(15) NOT NULL,
  `name` VARCHAR(100) NOT NULL,
  `port` INT(6) NOT NULL,
  PRIMARY KEY (`id`)
) ;

CREATE TABLE `sessions` (
  `id` CHAR(32) NOT NULL,
  `starttime` DATETIME NOT NULL,
  `endtime` DATETIME NULL DEFAULT NULL,
  `sensor` INT(11) NOT NULL,
  `ip` VARCHAR(15) NOT NULL DEFAULT '',
  `client` INT(4) NULL DEFAULT NULL,
  `port` INT(6) NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `starttime` (`starttime`, `sensor`)
) ;

CREATE TABLE `ttylog` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `channelid` CHAR(32) NOT NULL,
  `ttylog` MEDIUMBLOB NOT NULL,
  PRIMARY KEY (`id`)
) ;

CREATE TABLE `downloads` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `channelid` CHAR(32) NOT NULL,
  `timestamp` DATETIME NOT NULL,
  `url` TEXT NOT NULL,
  `outfile` TEXT NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `session` (`channelid`, `timestamp`)
) ;

CREATE TABLE `channels` (
  `id` CHAR(32) NOT NULL,
  `type` VARCHAR(10) NOT NULL,
  `starttime` DATETIME NOT NULL,
  `endtime` DATETIME NULL,
  `sessionid` CHAR(32) NOT NULL,
  PRIMARY KEY (`id`)
) ;

CREATE TABLE `commands` (
  `timestamp` DATETIME NOT NULL,
  `channelid` CHAR(32) NOT NULL,
  `command` VARCHAR(240) NOT NULL,
  PRIMARY KEY (`timestamp`, `command`)
) ;
