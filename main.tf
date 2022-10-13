# 1.create A VPC Infrastructure
resource "aws_vpc" "PAP-vpc" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "PAP-vpc"
  }
}
#  2.create public subnet1. 
resource "aws_subnet" "PAP-pub-sn1" {
  vpc_id            = aws_vpc.PAP-vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = var.az1
  tags = {
    Name = "PAP1-pub_sn1"
  }
}

# 3.create private subnet1
resource "aws_subnet" "PAP-prv-sn1" {
  vpc_id            = aws_vpc.PAP-vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = var.az1
  tags = {
    Name = "PAP-prv-sn1"
  }
}

# 4.create public subnet2. 
resource "aws_subnet" "PAP-pub-sn2" {
  vpc_id            = aws_vpc.PAP-vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = var.az2
  tags = {
    Name = "PAP-pub-sn2"
  }
}
# 5.create privat subnet2
resource "aws_subnet" "PAP-prv-sn2" {
  vpc_id            = aws_vpc.PAP-vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = var.az2
  tags = {
    Name = "PAP-prv-sn2"
  }
}
# 6.internet gateways
resource "aws_internet_gateway" "PAP-igw" {
  vpc_id = aws_vpc.PAP-vpc.id
  tags = {
    Name = "PAP-igw"
  }
}

# 7. route tables
resource "aws_route_table" "PAP-rt" {
  vpc_id = aws_vpc.PAP-vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.PAP-igw.id
  }

  tags = {
    Name = "PAP-rt"
  }
}
# 8. route table association for Pubblic Subnet1
resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.PAP-pub-sn1.id
  route_table_id = aws_route_table.PAP-rt.id
}

#  9. route table association for Private Subnet1. 
resource "aws_route_table_association" "b" {
  route_table_id = aws_route_table.PAP-rt.id
  subnet_id      = aws_subnet.PAP-prv-sn1.id
}
#  10. route table association for Pubblic Subnet2
resource "aws_route_table_association" "c" {
  subnet_id      = aws_subnet.PAP-pub-sn2.id
  route_table_id = aws_route_table.PAP-rt.id
}
#  11. route table association for Private Subnet2. 
resource "aws_route_table_association" "d" {
  route_table_id = aws_route_table.PAP-rt.id
  subnet_id      = aws_subnet.PAP-prv-sn2.id
}
# 12. Security/port
resource "aws_security_group" "PAP-fe-sg" {
  name        = "PAP-fe-sg"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.PAP-vpc.id 

ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  } 
ingress {
    description = "HTTP"
    from_port   = var.port_http
    to_port     = var.port_http
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
ingress {
    description = "jenkins"
    from_port   = var.port_proxy1
    to_port     = var.port_proxy1
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
ingress {
    description = "Docker"
    from_port   = var.port_proxy2
    to_port     = var.port_proxy2
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
ingress {
    description = "Sonarqube"
    from_port   = var.port_sonar
    to_port     = var.port_sonar
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
ingress {
    description = "SSH"
    from_port   = var.port_ssh
    to_port     = var.port_ssh
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "PAP-fe-sg"
  }
}
  
resource "aws_security_group" "PAP-be-sg" {
  name        = "PAP-be-sg"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.PAP-vpc.id 

  ingress {
    description = "TLS from VPC"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.2.0/24", "10.0.4.0/24"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "PAP-be-sg"
  }
}
#Create NAT gateway
resource "aws_nat_gateway" "PAP-ngw" {
  allocation_id = aws_eip.PAP-eip-nat.id
  subnet_id     = aws_subnet.PAP-pub-sn1.id

  tags = {
    Name = "PAP-ngw"
  }
}
#create elastic ip
resource "aws_eip" "PAP-eip-nat" {
  depends_on = [aws_internet_gateway.PAP-igw]
}
#Create a Keypair
resource "aws_key_pair" "PAP-key" {
  key_name   = var.keyname
  public_key = file(var.PAP-key)
}

# Create SonarQube Server
resource "aws_instance" "PAP-Sonarqube-Server" {
  ami                         = var.SonarQube-ami
  instance_type               = var.instance-type
  vpc_security_group_ids      = [aws_security_group.PAP-fe-sg.id]
  subnet_id                   = aws_subnet.PAP-pub-sn1.id
  key_name                    = var.keyname
  associate_public_ip_address = true
  user_data                   = <<-EOF
#!/bin/bash
sudo apt update -y  
echo "***Firstly Modify OS Level values***"  
sudo bash -c 'echo "
  vm.max_map_count=262144
  fs.file-max=65536
  ulimit -n 65536
  ulimit -u 4096" >> /etc/sysctl.conf'  
  sudo bash -c 'echo "
  sonarqube   -   nofile   65536
  sonarqube   -   nproc    4096" >> /etc/security/limits.conf'  
  echo "***********Install Java JDK***********"
  sudo apt install openjdk-11-jdk -y  
  echo "***********Install PostgreSQL***********"
  echo "***********The version of postgres currenlty is 14.5 which is not supported so we have to download v12***********"
  sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
  wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
  sudo apt-get update -y
  sudo apt-get -y install postgresql-12 postgresql-contrib-12  
  echo "*****Enable and start, so it starts when system boots up*******"
  sudo systemctl enable postgresql
  sudo systemctl start postgresql  
  #Change default password of postgres user
  sudo chpasswd <<<"postgres:password"  
  #Create user sonar without switching technically
  sudo su -c 'createuser sonar' postgres  
  #Create SonarQube Database and change sonar password
  sudo su -c "psql -c \"ALTER USER sonar WITH ENCRYPTED PASSWORD 'password'\"" postgres
  sudo su -c "psql -c \"CREATE DATABASE sonarqube OWNER sonar\"" postgres
  sudo su -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE sonarqube to sonar\"" postgres  
  #Restart postgresql for changes to take effect
  sudo systemctl restart postgresql  
  #Install SonarQube
  sudo mkdir /sonarqube/
  cd /sonarqube/
  sudo curl -O https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-9.6.1.59531.zip
  sudo apt install unzip -y
  sudo unzip sonarqube-9.6.1.59531.zip -d /opt/
  sudo mv /opt/sonarqube-9.6.1.59531/ /opt/sonarqube  
  #Add a new usergroup called sonar
  sudo groupadd sonar  
  #Then, create a user and add the user into the group with directory permission to the /opt/ directory
  sudo useradd -c "SonarQube - User" -d /opt/sonarqube/ -g sonar sonar  
  #Change ownership of the directory to sonar
  sudo chown sonar:sonar /opt/sonarqube/ -R  
  sudo bash -c 'echo "
  sonar.jdbc.username=sonar
  sonar.jdbc.password=Password
  sonar.jdbc.url=jdbc:postgresql://localhost/sonarqube
  sonar.search.javaOpts=-Xmx512m -Xms512m -XX:+HeapDumpOnOutOfMemoryError" >> /opt/sonarqube/conf/sonar.properties'  
  #Configure such that SonarQube starts on boot up
  sudo touch /etc/systemd/system/sonarqube.service  
  #Configuring so that we can run commands to start, stop and reload sonarqube service
  sudo bash -c 'echo "
  [Unit]
  Description=SonarQube service
  After=syslog.target network.target 

  [Service]
  Type=forking  
  
  ExecStart=/opt/sonarqube/bin/linux-x86-64/sonar.sh start
  ExecStop=/opt/sonarqube/bin/linux-x86-64/sonar.sh stop
  ExecReload=/opt/sonarqube/bin/linux-x86-64/sonar.sh restart  
  
  User=sonar
  Group=sonar
  Restart=always  
  
  LimitNOFILE=65536
  LimitNPROC=4096  
  
  [Install]
  WantedBy=multi-user.target" >> /etc/systemd/system/sonarqube.service'  
  
  #Enable and Start the Service
  sudo systemctl daemon-reload
  sudo systemctl enable sonarqube.service
  sudo systemctl start sonarqube.service  
  
  #Install net-tools incase we want to debug later
  sudo apt install net-tools -y  
  
  #Install nginx
  sudo apt-get install nginx -y  
  
  #Configure nginx so we can access server from outside
  sudo touch /etc/nginx/sites-enabled/sonarqube.conf
  sudo bash -c 'echo "
  server {
    listen 80;  

    access_log  /var/log/nginx/sonar.access.log;
    error_log   /var/log/nginx/sonar.error.log;    
    
    proxy_buffers 16 64k;
    proxy_buffer_size 128k;    
    
    location / {
        proxy_pass  http://127.0.0.1:9000;
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
        proxy_redirect off;        
        
        proxy_set_header    Host            \$host;
        proxy_set_header    X-Real-IP       \$remote_addr;
        proxy_set_header    X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header    X-Forwarded-Proto http;
    }
  }" >> /etc/nginx/sites-enabled/sonarqube.conf'  
  
  #Remove the default configuration file
  sudo rm /etc/nginx/sites-enabled/default  
  
  #Enable and restart nginix service
  sudo systemctl enable nginx.service
  sudo systemctl stop nginx.service
  sudo systemctl start nginx.service

  echo "****************Change Hostname(IP) to something readable**************"
  sudo hostnamectl set-hostname Sonarqube
  sudo reboot
  # echo "license_key: "license Key"" | sudo tee -a /etc/newrelic-infra.yml
  # sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
  # sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
  # sudo yum install newrelic-infra -y
  EOF
  tags = {
    Name = "PAP-SonarQube"
  }
}
#Create Doocker host Server
resource "aws_instance" "PAP-Docker-Server" {
  ami                         = var.ami
  instance_type               = var.instance-type
  vpc_security_group_ids      = [aws_security_group.PAP-fe-sg.id]
  subnet_id                   = aws_subnet.PAP-pub-sn1.id
  key_name                    = var.keyname
  associate_public_ip_address = true
  user_data                   = <<-EOF
    #!/bin/bash
    sudo yum update -y
    sudo yum install -y yum-utils
    sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    sudo yum install docker-ce docker-ce-cli containerd.io docker-compose-plugin -y
    sudo systemctl start docker
    echo "license_key: "license Key"" | sudo tee -a /etc/newrelic-infra.yml
    sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
    sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
    sudo yum install newrelic-infra -y
    sudo su
    echo "PubKeyAcceptedKeyTypes=+ssh-rsa" >> /etc/ssh/sshd_config.d/10-insecure-rsa-keysig.conf
    sudo service sshd reload
    chmod -R 700 .ssh/
    sudo chown -R ec2-user:ec2-user .ssh/
    chmod 600 .ssh/authorized_keys
    echo "${file(var.PAP-key)}" >> /home/ec2-user/.ssh/authorized_keys
    sudo hostnamectl set-hostname Docker
    # sudo groupadd docker && sudo usermod -aG docker ec2-user
    # sudo su
    # echo "Password" | sudo passwd ec2-user --stdin 
    # #echo "ec2-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
    # sed -ie 's@PasswordAuthentication no@PasswordAuthentication yes@' /etc/ssh/sshd_config
    # chmod 600 .ssh/authorized_keys
    # sudo service sshd restart
  EOF
  tags = {
    Name = "PAP-Docker-Server"
  }
}
# Create Jenkins-Server
resource "aws_instance" "PAP-Jenkins-Server" {
  ami                         = var.ami
  instance_type               = var.instance-type
  vpc_security_group_ids      = [aws_security_group.PAP-fe-sg.id]
  subnet_id                   = aws_subnet.PAP-pub-sn2.id
  key_name                    = var.keyname
  associate_public_ip_address = true
  user_data                   = <<-EOF
#!/bin/bash
# sudo yum update -y
# sudo yum install wget -y
# sudo yum install git -y
# sudo yum install maven -y
# sudo wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat-stable/jenkins.repo
# sudo rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io.key
# sudo yum upgrade -y
# sudo yum install jenkins java-11-openjdk-devel -y --nobest 
# sudo yum install epel-release java-11-openjdk-devel
# sudo systemctl daemon-reload
# sudo systemctl start jenkins
# sudo systemctl enable jenkins
# sudo yum install -y yum-utils
# sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
# sudo yum update -y
# sudo yum install docker-ce docker-ce-cli containerd.io -y
# sudo systemctl start docker
# sudo systemctl enable docker
# sudo usermod -aG docker ec2-user
# sudo usermod -aG docker jenkins
# echo "license_key: "license Key"" | sudo tee -a /etc/newrelic-infra.yml
# sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
# sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
# sudo yum install newrelic-infra -y
# sudo hostnamectl set-hostname Jenkins
sudo yum update -y
sudo yum install wget -y
sudo yum install git -y
sudo yum install -y yum-utils
sudo yum install -y http://mirror.centos.org/centos/7/extras/x86_64/Packages/sshpass-1.06-2.el7.x86_64.rpm
sudo yum install sshpass -y
sudo wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat-stable/jenkins.repo
sudo rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io.key
sudo yum upgrade -y
sudo yum install jenkins java-11-openjdk-devel -y --nobest
sudo systemctl daemon-reload
sudo systemctl start jenkins
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum update -y
sudo yum install docker-ce docker-ce-cli containerd.io -y
sudo systemctl start docker
sudo usermod -aG docker ec2-user
echo "license_key: "license Key"" | sudo tee -a /etc/newrelic-infra.yml
sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
sudo yum install newrelic-infra -y
sudo hostnamectl set-hostname Jenkins
EOF
  tags = {
    Name = "PAP-Jenkins-Server"
  }
}
data "aws_instance" "PAP-Docker-Server" {
  filter {
    name   = "tag:Name"
    values = ["PAP-Docker-Server"]
  }
  depends_on = [
    aws_instance.PAP-Docker-Server
  ]
  }  
data "aws_instance" "PAP-Ansible-Server" {
  filter {
    name   = "tag:Name"
    values = ["PAP-Ansible-Server"]
  }
  depends_on = [
    aws_instance.PAP-Ansible-Server
  ]
}
# Create Ansible host Server
resource "aws_instance" "PAP-Ansible-Server" {
  ami                         = var.ami
  instance_type               = var.instance-type
  vpc_security_group_ids      = [aws_security_group.PAP-fe-sg.id]
  subnet_id                   = aws_subnet.PAP-pub-sn1.id
  key_name                    = var.keyname
  associate_public_ip_address = true
  user_data                   = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
sudo yum install python3.8 -y
sudo alternatives --set python /usr/bin/python3.8
sudo yum -y install python3-pip
sudo yum install ansible -y
pip3 install ansible --user
sudo chown ec2-user:ec2-user /etc/ansible
sudo yum install -y http://mirror.centos.org/centos/7/extras/x86_64/Packages/sshpass-1.06-2.el7.x86_64.rpm
sudo yum install sshpass -y
echo "license_key: "license Key"" | sudo tee -a /etc/newrelic-infra.yml
sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
sudo yum -q makecache -y --disablerepo='*' --enablerepo='newrelic-infra'
sudo yum install newrelic-infra -y
sudo su
echo "PubKeyAcceptedKeyTypes=+ssh-rsa" >> /etc/ssh/sshd_config.d/10-insecure-rsa-keysig.conf
sudo service sshd reload
sudo bash -c 'echo "StrictHostKeyChecking No" >> /etc/ssh/ssh_config'
echo "${file(var.PAP-PRIV-key)}" >> /home/ec2-user/.ssh/anskey_rsa
echo "${file(var.PAP-key)}" >> /home/ec2-user/.ssh/anskey_rsa.pub 
# sudo su
# echo Admin123@ | passwd ec2-user --stdin
# echo "ec2-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
# sed -ie 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
# sudo service sshd reload
sudo chmod -R 700 .ssh/
sudo chown -R ec2-user:ec2-user .ssh/
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce -y
sudo systemctl start docker
sudo usermod -aG docker ec2-user
cd /etc
sudo chown ec2-user:ec2-user hosts
cat <<EOT>> /etc/ansible/hosts
localhost ansible_connection=local
[docker_host]
${data.aws_instance.PAP-Docker-Server.public_ip}  ansible_ssh_private_key_file=/home/ec2-user/.ssh/anskey_rsa
EOT
sudo mkdir /opt/docker
sudo chown -R ec2-user:ec2-user /opt/docker
sudo chmod -R 700 /opt/docker
touch /opt/docker/Dockerfile
cat <<EOT>> /opt/docker/Dockerfile
# pull tomcat image from docker hub
FROM tomcat
FROM openjdk:8-jre-slim
#copy war file on the container
COPY spring-petclinic-2.4.2.war app/
WORKDIR app/
RUN pwd
RUN ls -al
ENTRYPOINT [ "java", "-jar", "spring-petclinic-2.4.2.war", "--server.port=8085"]
EOT
touch /opt/docker/docker-image.yml
cat <<EOT>> /opt/docker/docker-image.yml
---
 - hosts: localhost
  #root access to user
   become: true

   tasks:
   - name: login to dockerhub
     command: docker login -u "user ID" -p "Password"#

   - name: Create docker image from Pet Adoption war file
     command: docker build -t pet-adoption-image .
     args:
       chdir: /opt/docker

   - name: Add tag to image
     command: docker tag pet-adoption-image "user ID"/pet-adoption-image

   - name: Push image to docker hub
     command: docker push "user ID"/pet-adoption-image

   - name: Remove docker image from Ansible node
     command: docker rmi pet-adoption-image "user ID"/pet-adoption-image
     ignore_errors: yes
EOT
touch /opt/docker/docker-container.yml
cat <<EOT>> /opt/docker/docker-container.yml
---
 - hosts: docker_host
   become: true

   tasks:
   - name: login to dockerhub
     command: docker login -u "user ID" -p "Password"#

   - name: Stop any container running
     command: docker stop pet-adoption-container
     ignore_errors: yes

   - name: Remove stopped container
     command: docker rm pet-adoption-container
     ignore_errors: yes

   - name: Remove docker image
     command: docker rmi "user ID"/pet-adoption-image
     ignore_errors: yes

   - name: Pull docker image from dockerhub
     command: docker pull "user ID"/pet-adoption-image
     ignore_errors: yes

   - name: Create container from pet adoption image
     command: docker run -it -d --name pet-adoption-container -p 8080:8085 "user ID"/pet-adoption-image
     ignore_errors: yes
EOT
cat << EOT > /opt/docker/monitoring.yml
---
 - hosts: docker
   become: true

   tasks:
   - name: install newrelic agent
     command: docker run \
                     -d \
                     --name newrelic-infra \
                     --network=host \
                     --cap-add=SYS_PTRACE \
                     --privileged \
                     --pid=host \
                     -v "/:/host:ro" \
                     -v "/var/run/docker.sock:/var/run/docker.sock" \
                     -e NRIA_LICENSE_KEY="license Key" \
                     newrelic/infrastructure:latest
EOT
sudo hostnamectl set-hostname Ansible
EOF
  tags = {
    Name = "PAP-Ansible-Server"
  }
}

# #Add an Application Load Balancer
# resource "aws_lb" "PAP-alb" {
#   name                       = "PAP-alb"
#   internal                   = false
#   load_balancer_type         = "application"
#   security_groups            = [aws_security_group.PAP-fe-sg.id]
#   subnets                    = [aws_subnet.PAP-pub-sn1.id, aws_subnet.PAP-pub-sn2.id]
#   enable_deletion_protection = false
# }
# #Add a load balancer Listener
# resource "aws_lb_listener" "PAP-alb-listener" {
#   load_balancer_arn = aws_lb.PAP-alb.arn
#   port              = "80"
#   protocol          = "HTTP"

#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.PAP-tg.arn
#   }
# }
# # Create a Target Group for Load Balancer
# resource "aws_lb_target_group" "PAP-tg" {
#   name     = "PAP-tg"
#   port     = 8080
#   protocol = "HTTP"
#   vpc_id   = aws_vpc.PAP-vpc.id
#   health_check {
#     healthy_threshold   = 3
#     unhealthy_threshold = 5
#     interval            = 30
#     timeout             = 5
#     path                = "/"
#   }
# }

# #Create Target group attachment
# resource "aws_lb_target_group_attachment" "PAP-tg-att-1" {
#   target_group_arn = aws_lb_target_group.PAP-tg.arn
#   target_id        = aws_instance.PAP-Docker-Server.id
#   port             = 8080
# }

# # Create PACJP1_Server AMI Image
# resource "aws_ami_from_instance" "PAP-Server-Image" {
#   name                    = "PAP-Server-Image"
#   source_instance_id      = aws_instance.PAP-Docker-Server.id
#   snapshot_without_reboot = true
#   depends_on = [
#     aws_instance.PAP-Docker-Server
#   ]
#   tags = {
#     Name = "PAP-Server-Image"
#   }
# }

# #Creating Launch Configuration

# resource "aws_launch_configuration" "PAP-Launch-Configuration" {
#   name_prefix   = "PAP-Launch-Configuration"
#   image_id      = var.ami
#   instance_type = var.instance-type
#   key_name = var.keyname
#   security_groups = ["${aws_security_group.PAP-fe-sg.id}"]
#   associate_public_ip_address = true
#   lifecycle {
#     create_before_destroy = true
#   }
# }

# #create autoscaling group
# resource "aws_autoscaling_group"  "PAP-asg"{
#   name                      = "PAP_asg"
#   max_size                  = 5
#   min_size                  = 2
#   health_check_grace_period = 60
#   health_check_type         = "EC2"
#   desired_capacity          = 3
#   force_delete              = true
  
#   launch_configuration      = aws_launch_configuration.PAP-Launch-Configuration.name

#   vpc_zone_identifier       = [aws_subnet.PAP-pub-sn1.id, aws_subnet.PAP-pub-sn2.id]

# }

# #Create Autoscaling Group Policy
# resource "aws_autoscaling_policy" "PAP-asg-policy" {
#   name                   = "PAP-asg-policy"
#    adjustment_type        = "ChangeInCapacity"
#   policy_type            = "TargetTrackingScaling"
#     autoscaling_group_name = aws_autoscaling_group.PAP-asg.name
# target_tracking_configuration {
#     predefined_metric_specification {
#       predefined_metric_type = "ASGAverageCPUUtilization"
#     }

#     target_value = 60.0
#   }
# }