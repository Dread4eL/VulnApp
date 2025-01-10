-- phpMyAdmin SQL Dump
-- version 5.1.2
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: Jan 16, 2024 at 09:57 PM
-- Server version: 5.7.24
-- PHP Version: 8.0.1

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `testdb`
--

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `firstName` varchar(100) DEFAULT NULL,
  `lastName` varchar(100) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `username` varchar(100) DEFAULT NULL,
  `password` varchar(100) DEFAULT NULL,
  `isModerator` tinyint(1) NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `firstName`, `lastName`, `email`, `username`, `password`, `isModerator`) VALUES
(1, 'Paul', 'FRADET', 'paul.fradet@gmail.com', 'Admin', 'ThisIsAReallyStr0ngP@ssw0rd__!', 1),
(2, 'Baptiste', 'SERIN', 'serinbaptiste@gmail.com', 'SerinooBaptman', '123456', 0),
(3, 'Romain', 'NTAMAK', 'rom1ntam@yahoo.fr', 'RomRomak', 'romntam123', 0),
(4, 'Gabin', 'VILLIERE', 'gab_vil@hotmail.fr', 'Gaboudu14', 'vilgab83!', 0),
(5, 'sebastien', 'CHABAL', 'chabaaal_seb@orange.fr', 'Chaboubou', 'rugbylover', 0),
(6, 'Dany', 'PRISOT', 'dany.prisot@gmail.com', 'danPris', 'soleil123', 0),
(7, 'Isa', 'FACUNDO', 'isafacund@hotmail.com', 'IsaFacky', 'facunisa789', 0),
(8, 'Antoine', 'DUPONT', 'antoine.dupont@gmail.com', 'AntoDupdup', 'best9inworld', 0),
(9, 'Pouet', 'Klouch', 'pouet.klouch@outlook.fr', 'PoutPout12', 'Kloucydu54', 0);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
