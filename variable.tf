variable "ami" {
  default = "ami-06640050dc3f556bb"
}
variable "SonarQube-ami" {
  default = "ami-08c40ec9ead489470"
}
variable "region" {
  default = "us-east-1"
}
variable "az1" {
  default = "us-east-1a"
}
variable "az2" {
  default = "us-east-1b"
}
variable "instance-type" {
  default = "t2.medium"
}
variable "PAP-key" {
  default     = "~/keypairs/key.pub"
  description = "path to my keypairs"
}
variable "PAP-PRIV-key" {
  default     = "~/keypairs/keyp"
  description = "path to my keypairs"
}
variable "db_instance_class" {
  default = "db.t2.micro"
}
variable "keyname" {
  default = "PAP-key"
}
variable "database_identifier" {
  default = "papjb1-db-id"
}
variable "vpc_id" {
default = "vpc-0e956f11ebd3cd342"
}
variable "port_proxy1" {
  default = 8080
}
variable "port_proxy2" {
  default = 8085
}
variable "port_http" {
  default = 80
}
variable "port_sonar" {
  default = 9000
}
variable "port_ssh" {
  default = 22
}