#include "Exceptions.hpp"
#include "Filter.hpp"
#include "RuleSet.hpp"

#include <cstring>
#include <fstream>
#include <iostream>

static int readRules(const char* type, const char* path, firewall::RuleSet& rules);

int main(int argc, char** argv)
{
  const char* usage =
    "Usage:\n"
    "  firewall <IFACE> <IFACE> whitelist <CONFIG-FILE>\n"
    "  firewall <IFACE> <IFACE> blacklist <CONFIG-FILE>\n";

  if (argc != 5) {
    std::cerr << usage;
    return 1;
  }

  firewall::RuleSet rules;
  int res = readRules(argv[3], argv[4], rules);
  if (res < 0) {
    std::cerr << usage;
    return 1;
  }
  std::cerr << "Config is OK!\n";

  firewall::Filter filter(std::move(rules));
  res = filter.start(argv[1], argv[2]);
  if (res < 0) {
    std::cerr << "Failed to connect to interfaces\n";
    std::cerr << usage;
    return 1;
  }
  
  std::string command;
  while (std::cin >> command) {
    if (command == "stop") {
      filter.stop();
      return 0;
    }
  }

  return 0;
}

static int readRules(const char* type, const char* path, firewall::RuleSet& rules) {
  std::ifstream file;
  file.open(path);
  if (!file) {
    std::cerr << "Failed to open file '" << path << "'\n";
    return -1;
  }

  try {
    if (strcmp("whitelist", type) == 0) {
      file >> firewall::RuleSet::whitelist(rules);
    }
    else if (strcmp("blacklist", type) == 0) {
      file >> firewall::RuleSet::blacklist(rules);
    }
    else {
      std::cerr << "Unrecognized option '" << type << "'\n";
      return -1;
    }
  } catch (const firewall::InvalidConfig& e) {
    std::cerr
      << "Invalid line #" << e.getLineNumber()
      << " '" << e.getLine() << "'\n";
    return -1;
  }

  return 0;
}
