// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "./verifier.sol";

interface IVerifier {
    function verifyTx(Verifier.Proof memory proof, uint256[1] memory input) external view returns (bool);
}

contract SoulBoundToken {
    

    uint256 private _tokenIdCounter;

    struct IDInfo {
        string name;
        uint256 id;
    }

    uint256 private currentTokenId;
    
    mapping(uint256 tokenId => address) private _owners;
    mapping(address owner => uint256) private _balances;
    mapping(uint256 id => address) private _idOwners;
    mapping(address => bool) public minters;

    //modifier onlyAccessThroughSignature(bytes32 _sig) {
    //    require(keccak256(abi.encodePacked(_sig)) == keccak256("Sign to get token info"), "Invalid signature");
    //    _;
    //}

    modifier onlyMinter() {
        require(minters[msg.sender], "Caller is not a minter");
        _;
    }

    Verifier verifier;

    constructor(address _verifierAddress) {
        verifier = Verifier(_verifierAddress);
    }

        // Function to grant minting permission to an address
    function grantMinter(address _minter) public  {
        minters[_minter] = true;
    }

    // Function to revoke minting permission from an address
    function revokeMinter(address _minter) public  {
        minters[_minter] = false;
    }

    // Mint function callable only by addresses with minting permission
    function mint(address _to, string memory _name, uint256 _id) public onlyMinter {

        require(_idOwnerOf(_id) == address(0), "Token ID already exists");
        
        uint256 newTokenId = currentTokenId;
        currentTokenId++;

        if (_to == address(0)) {
            revert("Wrong minter adress");
        }
        address previousOwner = _update(_to, newTokenId, _id);
        if (previousOwner != address(0)) {
            revert("Wrong previous owner");
        }

        _setIDInfo(newTokenId, _name, _id);
    }

    // Internal function to set token information
    function _setIDInfo(uint256 _tokenId, string memory _name, uint256 _id) internal {
        IDInfo memory info = IDInfo(_name, _id);
        tokenInfo[_tokenId] = info;
    }

    // Mapping to store additional token information
    mapping(uint256 => IDInfo) private tokenInfo;

    //function getTokenInfo(address owner) public view onlyAccessThroughSignature("getTokenInfo") returns (IDInfo memory) {
        
    //    uint256 tokenId = getTokenIdFromAddress(owner);

    //    return tokenInfo[tokenId];
    //}

    function getTokenInfo(address owner) public view returns (IDInfo memory) {
        
        uint256 tokenId = getTokenIdFromAddress(owner);    
        //require(testProof(), "Token verification failed");

        return tokenInfo[tokenId];
    }

    function getTokenIdFromAddress(address owner) public view returns (uint256) {
        for (uint256 i = 0; i < currentTokenId; i++) {
            if (_ownerOf(i) == owner) {
                return i;
            }
        
        }
        return 0;
    }

    function transferFrom(address from, address to, uint256 tokenId) public { revert("Your ID cannot be transfered"); }


    function burn(uint256 tokenId) external {
        require(ownerOf(tokenId) == msg.sender, "Only the owner of the ID can burn it.");

        address previousOwner = _update(address(0), tokenId, tokenInfo[tokenId].id);
        if (previousOwner == address(0)) {
            revert ("ERC721NonexistentToken");
        }
        delete tokenInfo[tokenId];

    }

    function _idOwnerOf(uint256 id) public view returns (address) {
        return _idOwners[id];
    }

    function _ownerOf(uint256 tokenId) internal view virtual returns (address) {
        return _owners[tokenId];
    }

    function ownerOf(uint256 tokenId) public view virtual returns (address) {
        return _requireOwned(tokenId);
    }

    function _requireOwned(uint256 tokenId) internal view returns (address) {
        address owner = _ownerOf(tokenId);
        if (owner == address(0)) {
            revert ("NonexistentToken");
        }
        return owner;
    }

    function _update(address to, uint256 tokenId, uint256 id/*, address auth*/) internal returns (address) {
        address from = _ownerOf(tokenId);

        // Execute the update
        if (from != address(0)) {

            unchecked {
                _balances[from] -= 1;
            }
        }

        if (to != address(0)) {
            unchecked {
                _balances[to] += 1;
            }
        }

        _owners[tokenId] = to;
        _idOwners[id]    = to;   

        return from;
    }

    function testProof() public view returns (bool) {
        uint256[2] memory a = [
            0x2f1a76ed3dd6bcaf2584a5dc76a33e2d04e8ec45fa69ab83324255faf5773292,
            0x29babe26ccd3206ba451972d995c70e7c0e37984e6bc25761cdcb53c9b8e3953
        ];
        uint256[2][2] memory b = [
            [
                0x020cecc344a6a08fbfa22af8495072a84eb3363db12260f5632246d8471f8e8e,
                0x28af39cd4a5f9883dc2c52c27e777818bc2886472d929a8866306a8a1d848d16
            ],
            [
                0x067e58fcc71b63e6250ec18dca01286ec87bc6306b7e16822ec35145611c9ef5,
                0x2bb106854e200ea5efee102f969fbfb8c382350b9fa6e5840553118fa268d419
            ]
        ];
        uint256[2] memory c = [
            0x1f9d025be628fa40b8f03f03ed2f5c38043945a3ba63ccc282756dfeb346bf28,
            0x2401a59f09e291b81f292090e54988a2f342950c0eafc2f37e0668ddf5a160b0
        ];
        uint256[3] memory input = [uint256(150), uint256(150), uint256(1)];

        Verifier.Proof memory proof;
        proof.a = Pairing.G1Point(a[0], a[1]);
        proof.b = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.c = Pairing.G1Point(c[0], c[1]);

        // Call the verifier contract
        return verifier.verifyTx(proof, input);
    }



}