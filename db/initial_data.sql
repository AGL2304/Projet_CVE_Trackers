-- Initial data for CVE Tracker - Assets
-- PostgreSQL format

CREATE TABLE IF NOT EXISTS assets (
  id VARCHAR(25) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  type VARCHAR(100) NOT NULL,
  ip VARCHAR(45),
  hostname VARCHAR(255),
  description TEXT,
  criticality VARCHAR(50) DEFAULT 'medium',
  status VARCHAR(50) DEFAULT 'active',
  createdAt TIMESTAMP DEFAULT NOW(),
  updatedAt TIMESTAMP DEFAULT NOW()
);

-- Insert initial assets
INSERT INTO assets (id, name, type, ip, hostname, description, criticality, status, createdAt, updatedAt) VALUES 
('cm0h7x2000001x000000x000000x00000001', 'Web Server Production', 'server', '192.168.1.10', 'web-prod-01', 'Serveur web principal pour l''application de production', 'critical', 'active', NOW(), NOW()),
('cm0h7x2000002x000000x000000x00000002', 'Database Server Primary', 'database', '192.168.1.20', 'db-prod-01', 'Base de données principale MySQL', 'critical', 'active', NOW(), NOW()),
('cm0h7x2000003x000000x000000x00000003', 'API Gateway', 'application', '192.168.1.30', 'api-gateway', 'Passerelle API pour le microservices', 'high', 'active', NOW(), NOW());

-- Initial data for CVE Tracker - Vulnerabilities
-- PostgreSQL format

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id VARCHAR(25) PRIMARY KEY,
  title VARCHAR(500) NOT NULL,
  description TEXT,
  severity VARCHAR(50) NOT NULL,
  status VARCHAR(50) DEFAULT 'open',
  cvssScore DECIMAL(5,2),
  cveId VARCHAR(50) UNIQUE,
  assetId VARCHAR(25),
  discoveredAt TIMESTAMP DEFAULT NOW(),
  resolvedAt TIMESTAMP,
  createdAt TIMESTAMP DEFAULT NOW(),
  updatedAt TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (assetId) REFERENCES assets(id) ON DELETE SET NULL
);

-- Insert initial vulnerabilities
INSERT INTO vulnerabilities (id, title, description, severity, status, cvssScore, cveId, assetId, discoveredAt, resolvedAt, createdAt, updatedAt) VALUES
('cm0h7x2000004x000000x000000x00000001', 'SQL Injection vulnerability in login form', 'Le formulaire de login est vulnérable aux injections SQL permettant aux attaquants de contourner l''authentification', 'critical', 'open', 9.8, 'CVE-2024-1001', 'cm0h7x2000001x000000x000000x00000001', NOW(), NULL, NOW(), NOW()),
('cm0h7x2000004x000000x000000x00000002', 'Cross-Site Scripting (XSS) in search functionality', 'La fonctionnalité de recherche est vulnérable aux attaques XSS stockées permettant l''exécution de scripts malveillants', 'high', 'open', 8.5, 'CVE-2024-1002', 'cm0h7x2000001x000000x000000x00000001', NOW(), NULL, NOW(), NOW()),
('cm0h7x2000004x000000x000000x00000003', 'Weak Password Policy', 'La politique de mots de passe ne respecte pas les standards de sécurité minimale', 'medium', 'open', 5.3, NULL, NULL, NOW(), NULL, NOW(), NOW()),
('cm0h7x2000004x000000x000000x00000004', 'Outdated OpenSSL Version', 'Le serveur utilise une version d''OpenSSL avec des vulnérabilités connues', 'high', 'in_progress', 7.2, 'CVE-2024-1005', 'cm0h7x2000002x000000x000000x00000001', NOW(), NULL, NOW(), NOW());

-- Initial data for CVE Tracker - CVEs
-- PostgreSQL format

CREATE TABLE IF NOT EXISTS cves (
  id VARCHAR(25) PRIMARY KEY,
  cveId VARCHAR(50) UNIQUE NOT NULL,
  description TEXT NOT NULL,
  severity VARCHAR(50) NOT NULL,
  cvssScore DECIMAL(5,2),
  cvssVector VARCHAR(255),
  publishedDate TIMESTAMP,
  lastModifiedDate TIMESTAMP,
  references TEXT,
  vulnStatus VARCHAR(100),
  importedAt TIMESTAMP DEFAULT NOW(),
  createdAt TIMESTAMP DEFAULT NOW(),
  updatedAt TIMESTAMP DEFAULT NOW()
);

-- Insert initial CVEs
INSERT INTO cves (id, cveId, description, severity, cvssScore, publishedDate, lastModifiedDate, vulnStatus, importedAt, createdAt, updatedAt) VALUES
('cm0h7x2000005x000000x000000x00000001', 'CVE-2024-1001', 'SQL Injection vulnerability in login form allowing attackers to bypass authentication', 'critical', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L', '2024-01-01 10:00:00', '2024-01-15 12:00:00', 'Analyzed', NOW(), NOW(), NOW()),
('cm0h7x2000005x000000x000000x00000002', 'CVE-2024-1002', 'XSS vulnerability in search functionality enabling stored attacks', 'high', 8.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I/L/A:L', '2024-01-02 08:00:00', '2024-01-10 14:00:00', 'Analyzed', NOW(), NOW(), NOW()),
('cm0h7x2000005x000000x000000x00000003', 'CVE-2024-1003', 'Unrestricted file upload vulnerability allowing arbitrary code execution', 'critical', 9.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L', '2024-01-03 12:00:00', '2024-01-20 16:00:00', 'Analyzed', NOW(), NOW(), NOW());
