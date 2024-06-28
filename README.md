Digital identification system on Scroll testnet is built and methods for implementing the above mentioned properties are as follows:

•	ERC-721 non-fungible token standard is used for having unique tokens that will serve as ID`s. A minting function is written for ID obtaining process that results in each person having a unique NFT. Each NFT holds information about the person that minted it. It holds name and ID number for this implementation, but additional information can be obtained if a system wants to store more. Proposed system requires every ID number to be unique and it guarantees that no NFT with the same ID number is minted on the smart contract.
•	Soulbound non-fungible token idea is used for this implementation. Trying to transfer the ID will result in a reverted transaction. Thus, identity thefts and malicious people using other identities is prevented.
•	In case of a death or ID change, an ID needs to be got rid of. A burn function is implemented for cases like these that sends the NFT to a burn address that no one has access to, practically burning it.
•	Information that is stored in the NFT can be accessed through poking the smart contract with a read call. Security of the information is ensured by adding a requirement that checks whether the address trying to read the ID information in the NFT, actually has the NFT or not. It reverts the read call if an address tries to read someone else`s NFT information. Thus, only action that can be done with ID is burning it or reading ID information after minting. Also, added a zero-knowledge proof system that verifies owner and caller are the same. There is only one proof for this case but it is planned to implement proof generation for every call.
•	A function is added to the smart contract that grants minting access to an address written inside the function. Only the deployer of the contract has the ability to grant minting access to prevent anyone having access to the digital identity system that might result in people which are not meant to have an ID end up having one by getting an illegal access. Also, a function that revokes access from an address that access is given before is also implemented to prevent abuse of access power by malicious users.

Website

Built a website for this project: https://cyber-id-nine.vercel.app/

If you dont have minting access, minting page is not visible. When an access is granted, user can mint its ID, then the user can see the ID information or burn the ID.

![ss1](https://github.com/yigitcanga/Scroll_idSBT/assets/105357336/9e041e92-836e-443a-8eff-caec54f2a720)

![ss2](https://github.com/yigitcanga/Scroll_idSBT/assets/105357336/4493f949-913f-4708-b45b-473228b2e443)

![ss3](https://github.com/yigitcanga/Scroll_idSBT/assets/105357336/efa379c7-8d70-4776-b2b7-dbd533b37836)

