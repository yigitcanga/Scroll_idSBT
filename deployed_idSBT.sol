// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x2c3a4ed5ca281d2b7e5ae6a7d6e24a8f00240a5a1f1c183d6535b21ea2f83ddd), uint256(0x1ded1b25571da3a3fa54a10ebcca3d6bd61a890c2b71969f24c9de99c50fd8e5));
        vk.beta = Pairing.G2Point([uint256(0x145f0804efb4e7252966aec4f79988d13fc3173abbd27b87853cd60b4bc8c30e), uint256(0x14cacf1bb96ac5c87f08dec1c8ee0dc2ae36011a9079d9926d58bd8a767b97a7)], [uint256(0x016aac3d71ed5c9f62d5eb646fb73441e2d15d0d36edd9eb4bdec305737de1a1), uint256(0x1a0e36378be5b20625a67b933f9bdd86db76638ad1848f8dc1d14c13f3690bb4)]);
        vk.gamma = Pairing.G2Point([uint256(0x14381a9a9cfe5fa5bcf839e77e04225ef7f68d0ab52a50b92e1a86319826735f), uint256(0x20eac850e2bb2664a0dfea3601e0fcaee530a0eea522a6e977d2566047b8dfd1)], [uint256(0x1868c983408f161472efbd2237affa1862a68bd57135cb8536799d8f229e0c3c), uint256(0x0990c4e3fd620868841bba05ccaf55e17e1bffebbe45834f105b8a1e2b70255d)]);
        vk.delta = Pairing.G2Point([uint256(0x17c5cf08e72d17b3423a394490a7b070e76319daecc002103fe20accefde7ec4), uint256(0x1b7e726ee4d89e57d6de6bbaddd973232ee5924d5e20dee173b7ed83ed967c44)], [uint256(0x209f3a3c102bea46d010c20a5085f54db165f770405ea29c630c04dcf862bdf2), uint256(0x08251076b35acaef7d34c6ef729d07ee2feb81d14063a8ea570240da7c81d961)]);
        vk.gamma_abc = new Pairing.G1Point[](4);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0ce0c8333b138190f96f174814617714e2322348a3b7c29ebd0466e4c2eeaf1d), uint256(0x2676218a7cf6b8058a6f244ee5f355aa836f58c2167dcd8276f0bbd82e9d4bdc));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x08964c28404a2b642776f7fc3338fd862b22bf2d52fe41f36edf7ead37a35931), uint256(0x1ae2e07f0a5574f8ea31f1d043c16a192900f3b60e496c4e2ba56707015a5998));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0256b0936870d833fcd21032bef7305827727ce00148d22058efd66593bda133), uint256(0x0ed814c36c9cf82bbcacc5e06e2ce403241f0646a4b3504f3c2709cdd069db12));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2a96a1a9f717e768d3272f4d0cf4b842bdb6f934df6cc66967cd96584eadc547), uint256(0x2ebd66fcf95b672b5f6f5cf10ec6e7a17909b50d88c2ed50f3aa905e83977438));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[3] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](3);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
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
