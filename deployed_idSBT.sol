/**
 *Submitted for verification at sepolia.scrollscan.com on 2024-07-04
*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

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


pragma solidity ^0.8.0;
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
        vk.alpha = Pairing.G1Point(uint256(0x0bdb26a0360323d29771c49a4a0342c7b193c8684d4a266b59d67a2069b94de9), uint256(0x179fd4d2bb01524e5dfb32409b653bc67611566448c127a96c19a419d1115b99));
        vk.beta = Pairing.G2Point([uint256(0x157a84dfa393fc0cbf1fd0efa80ca6c226f2ca22cff480e77a4b990c97f15881), uint256(0x17a34db5dd02ae8a05ffab1697e9f5a6cb97a3b444379a79c50ff9d4a2de01ae)], [uint256(0x2365474d93ba0effc91888c2958e0256f8abf0ef971d575bbc4196245b9e5f3f), uint256(0x201ea15beb455bc6fa02fcb9d7d0c26faac474aa0ba426103c8413408f676b47)]);
        vk.gamma = Pairing.G2Point([uint256(0x2699b389895a7a709afdebfd31e3fa52fbd183739f743c2d3ec3e1609c44295f), uint256(0x0d8e817bc1fa2cc19ea1c7f11c08e4b7e093296f440e2c6b67d4d62dc358401d)], [uint256(0x23b02da44579ad133f8cffafa82af267da79e567f08f7f8901bba48d4ace3c40), uint256(0x1fc6cfb8f8d63b7fe44e22b3db8f3150d9d8b0a787e568619ac6f2796dd82649)]);
        vk.delta = Pairing.G2Point([uint256(0x2dff64c68b0743ab848e023bc5c5c82156cb665ca13bb2532960ba6202327c6f), uint256(0x25bf67a832351324503f2784212a4d756b463ab38604fbd02e21a073a575f5fd)], [uint256(0x21be0f86618a7c22a721e1956a8faf613d303a0817a41994ee34134e357478cc), uint256(0x06fab8db0a2efc771d53826494c9c4e173d3b90f9d9d1097621fcd59a0ab0cb2)]);
        vk.gamma_abc = new Pairing.G1Point[](4);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x224eb5346983e655f8d0db0eb8ab9fbc657ce82cbdf1c9edb4f3772307dc7b8f), uint256(0x087ceccfbc996233deb60e9ea463f754cbf33db778aa8356e7afc82af7f06778));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0a702b24a38da723ebb946e07669611a6fb8a8581dd970a16c42dcd6d27a5c7a), uint256(0x1bd0996800906895281b23cbab30cbf621ed2502a5b5e875e07c3d9dbed8ec70));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x10251043ae4c1bac4e8082560f562d9910e516ddfd6ae999ac6feef2b554c97e), uint256(0x2652135e624cd74c2673ffc8b67902bda496da99476dfa72bff04f21fe581e88));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x098c09f86cfa9457901b4ada33d6487da08fb6e208b3c61d4b94430a0bce942b), uint256(0x21ba13d96379a4cd568de22c8123d2e69df4aaf22900dfef762408df6db29f05));
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
