output "Sonarqube-ip" {
  value = aws_instance.PAP-Sonarqube-Server.public_ip
}
 output "Docker-ip" {
   value = aws_instance.PAP-Docker-Server.public_ip
}
output "Jenkins_ip" {
  value = aws_instance.PAP-Jenkins-Server.public_ip
}
output "Ansible-ip" {
  value = aws_instance.PAP-Ansible-Server.public_ip
}
# output "LB_dns" {
#   value = aws_lb.PAP-alb.dns_name
# }
# output "Nameserver" {
#   value = aws_route53_zone.PAP-zone.name_servers
# }