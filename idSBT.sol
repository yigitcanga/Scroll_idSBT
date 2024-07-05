// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "./verifier.sol";

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

    function testProof(bytes memory proofData, uint256[] memory inputs) public view returns (bool) {
        
        Verifier.Proof memory proof = deserializeProof(proofData);

        // Prepare input array for verification
        uint256[3] memory inputArr = [inputs[0], inputs[1], inputs[2]];

        // Call the verifier contract's verifyTx function
        return verifier.verifyTx(proof, inputArr);
    }

        function deserializeProof(bytes memory proofData) internal pure returns (Verifier.Proof memory proof) {
        (
            uint256 aX,
            uint256 aY,
            uint256[2] memory bX,
            uint256[2] memory bY,
            uint256 cX,
            uint256 cY
        ) = abi.decode(proofData, (uint256, uint256, uint256[2], uint256[2], uint256, uint256));

        proof = Verifier.Proof({
            a: Pairing.G1Point(aX, aY),
            b: Pairing.G2Point(bX, bY),
            c: Pairing.G1Point(cX, cY)
        });
    }

    function getAddresses(address _owner) public view returns (address, address) {
        return (_owner, msg.sender);
    }

}
