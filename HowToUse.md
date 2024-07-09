# EPYC-7X Blockchain Application Instruction Manual

## Introduction

EPYC-7X is a blockchain-based cryptocurrency system built using Python and Flask, with a graphical user interface (GUI) using Tkinter. This manual provides step-by-step instructions to set up and use the EPYC-7X blockchain application.

### Features

- **Blockchain Functionality**: Mine blocks, add transactions, view the blockchain, check validity, and replace the chain.
- **GUI Interface**: Intuitive buttons for blockchain operations.
- **Secure Transactions**: Uses cryptography for transaction signing and verification.

## System Requirements

Ensure your system meets the following requirements:

- **Operating System**: Windows, macOS, or Linux
- **Software Dependencies**: Python 3.7 or higher, Flask, Tkinter (usually included with Python)

## Installation Steps

### 1. Clone the Repository

Clone the EPYC-7X repository from GitHub or download and extract the ZIP file.

-bash-
git clone https://github.com/PARADOXzss/EPYC-7X
cd EPYC-7X


### 2. Install Dependencies

Install necessary Python packages using pip.

-bash-
pip install flask requests


### 3. Run the Blockchain Server

Start the Flask server to run the blockchain backend.

-bash-
python blockchain_gui.py


### 4. Launch the GUI

Launch the GUI to interact with the blockchain system.

-bash-
python blockchain_gui.py


## Using the EPYC-7X Blockchain GUI

### GUI Layout

The GUI window includes the following buttons:

- **View Chain**: Display the current blockchain.
- **Mine Block**: Mine a new block.
- **Add Transaction**: Add a new transaction to the blockchain.
- **Check Validity**: Check if the blockchain is valid.
- **Connect Node**: Connect a new node to the blockchain network.
- **Replace Chain**: Replace the current blockchain with the longest valid chain.

### Basic Operations

1. **View Chain**:
   - Click on **View Chain** button to display the current state of the blockchain in a message box.

2. **Mine Block**:
   - Click on **Mine Block** button to mine a new block and add it to the blockchain. You will receive a confirmation message upon successful mining.

3. **Add Transaction**:
   - Click on **Add Transaction** button to add a new transaction. Enter the recipient's address and amount in the message box that appears. You will receive a confirmation message upon successful transaction addition.

4. **Check Validity**:
   - Click on **Check Validity** button to verify the integrity of the blockchain. A message box will display whether the blockchain is valid or not.

5. **Connect Node**:
   - Click on **Connect Node** button to add a new node to the blockchain network. Enter the node's address in the message box that appears. You will receive a confirmation message upon successful node connection.

6. **Replace Chain**:
   - Click on **Replace Chain** button to replace the current blockchain with the longest valid chain in the network. You will receive a confirmation message upon successful chain replacement.

## Troubleshooting

If you encounter any issues during setup or operation, consider the following:

- **Dependencies**: Ensure all required Python packages (`flask`, `requests`, `tkinter`) are installed.
- **Server**: Check that the Flask server is running (`python blockchain_gui.py`).
- **Network**: Verify network connectivity and firewall settings if connecting nodes.

## Security Considerations

- **Wallet Security**: Manage private keys securely. The EPYC-7X application uses cryptography for transaction signing and verification.
- **Network Security**: Use secure connections (HTTPS) when deploying to a production environment.
