CREATE DATABASE IF NOT EXISTS `wms`;
USE `wms`;

DROP TABLE IF EXISTS `locations`;
CREATE TABLE `locations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `locations` (`id`,`name`) VALUES (1,'Réception');
INSERT INTO `locations` (`id`,`name`) VALUES (2,'Stock Central');
INSERT INTO `locations` (`id`,`name`) VALUES (3,'Zone Expédition');
INSERT INTO `locations` (`id`,`name`) VALUES (4,'Réception');
INSERT INTO `locations` (`id`,`name`) VALUES (5,'Stock Central');
INSERT INTO `locations` (`id`,`name`) VALUES (6,'Zone Expédition');

DROP TABLE IF EXISTS `products`;
CREATE TABLE `products` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `products` (`id`,`name`) VALUES (1,'Widget A');
INSERT INTO `products` (`id`,`name`) VALUES (2,'Widget B');
INSERT INTO `products` (`id`,`name`) VALUES (3,'Gadget C');
INSERT INTO `products` (`id`,`name`) VALUES (4,'Widget A');
INSERT INTO `products` (`id`,`name`) VALUES (5,'Widget B');
INSERT INTO `products` (`id`,`name`) VALUES (6,'Gadget C');

DROP TABLE IF EXISTS `stock_moves`;
CREATE TABLE `stock_moves` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `product_id` int(11) NOT NULL,
  `from_location_id` int(11) DEFAULT NULL,
  `to_location_id` int(11) DEFAULT NULL,
  `quantity` decimal(10,2) NOT NULL,
  `move_type` varchar(50) NOT NULL,
  `moved_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `product_id` (`product_id`),
  KEY `from_location_id` (`from_location_id`),
  KEY `to_location_id` (`to_location_id`),
  CONSTRAINT `stock_moves_ibfk_1` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`),
  CONSTRAINT `stock_moves_ibfk_2` FOREIGN KEY (`from_location_id`) REFERENCES `locations` (`id`),
  CONSTRAINT `stock_moves_ibfk_3` FOREIGN KEY (`to_location_id`) REFERENCES `locations` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `stock_moves` (`id`,`product_id`,`from_location_id`,`to_location_id`,`quantity`,`move_type`,`moved_at`) VALUES (1,1,1,2,'100.00','IN','2026-01-10 08:30:00');
INSERT INTO `stock_moves` (`id`,`product_id`,`from_location_id`,`to_location_id`,`quantity`,`move_type`,`moved_at`) VALUES (2,2,2,3,'20.00','OUT','2026-01-11 14:15:00');
INSERT INTO `stock_moves` (`id`,`product_id`,`from_location_id`,`to_location_id`,`quantity`,`move_type`,`moved_at`) VALUES (3,3,1,2,'50.00','IN','2026-01-12 09:00:00');
INSERT INTO `stock_moves` (`id`,`product_id`,`from_location_id`,`to_location_id`,`quantity`,`move_type`,`moved_at`) VALUES (4,1,2,3,'10.00','OUT','2026-01-13 16:45:00');
INSERT INTO `stock_moves` (`id`,`product_id`,`from_location_id`,`to_location_id`,`quantity`,`move_type`,`moved_at`) VALUES (5,1,1,2,'100.00','IN','2026-01-10 08:30:00');
INSERT INTO `stock_moves` (`id`,`product_id`,`from_location_id`,`to_location_id`,`quantity`,`move_type`,`moved_at`) VALUES (6,2,2,3,'20.00','OUT','2026-01-11 14:15:00');
INSERT INTO `stock_moves` (`id`,`product_id`,`from_location_id`,`to_location_id`,`quantity`,`move_type`,`moved_at`) VALUES (7,3,1,2,'50.00','IN','2026-01-12 09:00:00');
INSERT INTO `stock_moves` (`id`,`product_id`,`from_location_id`,`to_location_id`,`quantity`,`move_type`,`moved_at`) VALUES (8,1,2,3,'10.00','OUT','2026-01-13 16:45:00');

