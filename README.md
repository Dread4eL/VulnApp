# VulnAPP: Vulnerable Security WebApp with Real-time Monitoring with ELK

## Description

VulnApp is an Information Security Management project that demonstrates real-time security monitoring using the ELK stack (Elasticsearch, Logstash, and Kibana) and MySQL. It collects and analyzes system logs to identify potential security threats and provides a centralized dashboard for visualization and analysis.

## Key Features

- **Purposeful Vulnerabilities:** The web app includes intentional security flaws to highlight common vulnerabilities such as SQL injection, XSS, and authentication weaknesses.
- **Real-time Alerts:** Generates real-time alerts for suspicious activities or attacks targeting the application.
- **Centralized Log Management:** Collects and processes logs from the web app and supporting systems.
- **Visualization Dashboards:** Provides interactive Kibana dashboards to display attack patterns, trends, and anomalies.
- **Modular Configuration:** Allows for easy addition of new log sources and customization of monitoring rules.

## Installation

### Prerequisites

- Ubuntu 20.04 LTS
- Root or sudo privileges

### Steps

#### 1. Clone the repository

```bash
git clone https://github.com/Dread4eL/VulnApp.git
cd VulnApp
```

#### 2. Install the ELK Stack

**Install Elasticsearch**

```bash
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```

Edit the Elasticsearch configuration file:

```bash
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Uncomment and set the `network.host` parameter:

```yaml
network.host: 0.0.0.0
```

Start and enable the Elasticsearch service:

```bash
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch
```

Verify Elasticsearch is running:

```bash
curl -X GET "localhost:9200" -H 'Content-Type: application/json'
```

**Install Logstash**

```bash
sudo apt install logstash
sudo systemctl enable logstash
```

**Install Kibana**

```bash
wget https://artifacts.elastic.co/downloads/kibana/kibana-7.10.2-amd64.deb
sudo dpkg -i kibana-7.10.2-amd64.deb
sudo systemctl enable kibana
sudo systemctl start kibana
```

Verify Kibana is running by accessing: `http://your-server-ip:5601`.

#### 3. Install and Configure MySQL

```bash
sudo apt update
sudo apt install mysql-server -y
sudo mysql_secure_installation
```

Create the database and user:

```sql
CREATE DATABASE testDBusers;
CREATE USER 'NewUser'@'localhost' IDENTIFIED BY 'pouet';
GRANT ALL PRIVILEGES ON testDBusers.* TO 'NewUser'@'localhost';
FLUSH PRIVILEGES;
```

Import the schema and sample data:

```bash
mysql -u NewUser -p testDBusers < users.sql
```

#### 4. Configure Logstash

Create input and output configuration files:

```bash
sudo nano /etc/logstash/conf.d/02-beats-input.conf
```

Insert the following:

```bash
input {
  beats {
    port => 5044
  }
}
```

Save and close the file.

```bash
sudo nano /etc/logstash/conf.d/30-elasticsearch-output.conf
```

Insert the following:

```bash
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
  }
}
```

Save and close the file.

Create an additional configuration file:

```bash
sudo nano /etc/logstash/conf.d/VulnApp.conf
```

Insert the following:

```bash
input {
  udp {
    port => 5959
    codec => json
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "vulnapp-logs-%{+YYYY.MM.dd}"
  }
  stdout {
    codec => rubydebug
  }
}
```

Save and close the file.

Test the configuration:

```bash
sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
```


#### 5. Start the Services

```bash
sudo systemctl start elasticsearch
sudo systemctl start logstash
sudo systemctl start kibana
sudo systemctl start mysql
```

## Usage

1. Access the Kibana dashboard at: `http://your-server-ip:5601`
2. Explore the pre-built dashboards to visualize security events.
3. Create new visualizations and dashboards to analyze specific threats or patterns.
4. Use the Discover tab in Kibana to search and filter log data.

## Customization

- **Logstash Pipelines:** Modify the logstash `.conf` files to add or customize input, filter, and output plugins for different log sources and security rules.
- **Kibana Visualizations:** Create custom visualizations and dashboards in Kibana to meet your specific security monitoring needs.

## Troubleshooting

- **Elasticsearch Errors:** Check the Elasticsearch logs (`/var/log/elasticsearch/`) for any errors.
- **Logstash Errors:** Check the Logstash logs (`/var/log/logstash/`) for any configuration or parsing errors.
- **Kibana Errors:** Check the Kibana logs (`/var/log/kibana/`) for any issues.
- **MySQL Errors:** Check the MySQL error log for any database-related problems.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## License

MIT License
