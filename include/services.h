#pragma once
#include <unordered_map>
#include <string>

const std::unordered_map<int, std::string> port_to_service = {
    { 21, "ftp" },
    { 22, "ssh" },
    { 23, "telnet" },
    { 25, "smtp" },
    { 53, "dns" },
    { 80, "http" },
    { 110, "pop3" },
    { 143, "imap" },
    { 443, "https" },
    { 3306, "mysql" },
    { 5000, "upnp" },
    { 7000, "afs3-fileserver" },
    // Add more ports and their services as needed
};
