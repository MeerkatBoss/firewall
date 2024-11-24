#include <iostream>

int main()
{
  const char* usage =
    "Usage:\n"
    "  firewall from <IFACE> to <IFACE> whitelist <CONFIG-FILE>\n"
    "  firewall from <IFACE> to <IFACE> blacklist <CONFIG-FILE>\n";
  std::cout << usage << '\n';
  return 2;
}
