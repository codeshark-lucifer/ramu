#include <windows.h>

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>

struct Player
{
    int health = 100;
    int maxHealth = 100;

    float stamina = 75.5f;
    float speed = 5.0f;

    double money = 250.50;

    bool godMode = false;
};

Player player;


// ============================================================
// Show player state
// ============================================================

void show()
{
    system("cls");

    std::cout << "==============================\n";
    std::cout << "          DEMO GAME\n";
    std::cout << "==============================\n\n";

    std::cout
        << "PID: "
        << GetCurrentProcessId()
        << "\n\n";

    std::cout
        << std::fixed
        << std::setprecision(2);

    std::cout
        << "Health  : "
        << player.health
        << " / "
        << player.maxHealth
        << "\n";

    std::cout
        << "Stamina : "
        << player.stamina
        << "\n";

    std::cout
        << "Speed   : "
        << player.speed
        << "\n";

    std::cout
        << "Money   : $"
        << player.money
        << "\n";

    std::cout
        << "GodMode : "
        << (player.godMode ? "ON" : "OFF")
        << "\n";

    std::cout << "\nAddresses:\n";

    std::cout
        << "health  = "
        << &player.health
        << "\n";

    std::cout
        << "stamina = "
        << &player.stamina
        << "\n";

    std::cout
        << "speed   = "
        << &player.speed
        << "\n";

    std::cout
        << "money   = "
        << &player.money
        << "\n";
}


// ============================================================
// Help
// ============================================================

void help()
{
    std::cout << R"(

Commands
--------------------------------

show
    Show current player values

h <value>
    Set health

h +<value>
    Increase health

h -<value>
    Decrease health


s <value>
    Set stamina

s +<value>
    Increase stamina

s -<value>
    Decrease stamina


sp <value>
    Set speed

m <value>
    Set money

g
    Toggle god mode

help
    Show this help

exit
    Quit


Examples
--------------------------------

h 100
h 50

h +10
h -20

s 100
s -5

sp 10

m 9999

g

)";
}


// ============================================================
// Command processing
// ============================================================

bool executeCommand(
    const std::string& line)
{
    std::stringstream ss(line);

    std::string command;
    std::string value;

    ss >> command;

    if (command.empty())
        return true;


    // --------------------------------------------------------
    // EXIT
    // --------------------------------------------------------

    if (command == "exit" ||
        command == "quit")
    {
        return false;
    }


    // --------------------------------------------------------
    // HELP
    // --------------------------------------------------------

    if (command == "help")
    {
        help();
        return true;
    }


    // --------------------------------------------------------
    // SHOW
    // --------------------------------------------------------

    if (command == "show")
    {
        show();
        return true;
    }


    // --------------------------------------------------------
    // HEALTH
    // --------------------------------------------------------

    if (command == "h" ||
        command == "health")
    {
        ss >> value;

        if (value.empty())
        {
            std::cout
                << "Usage: h <value>\n";

            return true;
        }

        try
        {
            int amount =
                std::stoi(value);

            if (value[0] == '+' ||
                value[0] == '-')
            {
                player.health += amount;
            }
            else
            {
                player.health = amount;
            }

            std::cout
                << "Health = "
                << player.health
                << "\n";
        }
        catch (...)
        {
            std::cout
                << "Invalid health value.\n";
        }

        return true;
    }


    // --------------------------------------------------------
    // STAMINA
    // --------------------------------------------------------

    if (command == "s" ||
        command == "stamina")
    {
        ss >> value;

        if (value.empty())
        {
            std::cout
                << "Usage: s <value>\n";

            return true;
        }

        try
        {
            float amount =
                std::stof(value);

            if (value[0] == '+' ||
                value[0] == '-')
            {
                player.stamina += amount;
            }
            else
            {
                player.stamina = amount;
            }

            std::cout
                << "Stamina = "
                << player.stamina
                << "\n";
        }
        catch (...)
        {
            std::cout
                << "Invalid stamina value.\n";
        }

        return true;
    }


    // --------------------------------------------------------
    // SPEED
    // --------------------------------------------------------

    if (command == "sp" ||
        command == "speed")
    {
        ss >> value;

        if (value.empty())
        {
            std::cout
                << "Usage: sp <value>\n";

            return true;
        }

        try
        {
            player.speed =
                std::stof(value);

            std::cout
                << "Speed = "
                << player.speed
                << "\n";
        }
        catch (...)
        {
            std::cout
                << "Invalid speed value.\n";
        }

        return true;
    }


    // --------------------------------------------------------
    // MONEY
    // --------------------------------------------------------

    if (command == "m" ||
        command == "money")
    {
        ss >> value;

        if (value.empty())
        {
            std::cout
                << "Usage: m <value>\n";

            return true;
        }

        try
        {
            player.money =
                std::stod(value);

            std::cout
                << "Money = $"
                << player.money
                << "\n";
        }
        catch (...)
        {
            std::cout
                << "Invalid money value.\n";
        }

        return true;
    }


    // --------------------------------------------------------
    // GOD MODE
    // --------------------------------------------------------

    if (command == "g" ||
        command == "god")
    {
        player.godMode =
            !player.godMode;

        std::cout
            << "GodMode = "
            << (player.godMode ? "ON" : "OFF")
            << "\n";

        return true;
    }


    // --------------------------------------------------------
    // UNKNOWN
    // --------------------------------------------------------

    std::cout
        << "Unknown command: "
        << command
        << "\n";

    std::cout
        << "Type 'help' for commands.\n";

    return true;
}


// ============================================================
// Main
// ============================================================

int main()
{
    SetConsoleTitleA(
        "Demo Game - Memory Test"
    );

    show();

    std::cout << "\n";
    std::cout
        << "Type 'help' for commands.\n";

    std::string line;

    while (true)
    {
        std::cout << "\nGame> ";

        if (!std::getline(
                std::cin,
                line))
        {
            break;
        }

        if (!executeCommand(line))
            break;
    }

    return 0;
}