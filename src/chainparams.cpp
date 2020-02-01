// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "This is Herbsters, that it is you otherb";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.BIP34Height = 710000;
        consensus.BIP34Hash = uint256S("fa09d204a83a768ed5a7c8d441fa62f2043abf420cff1226c7b4329aeb9d51cf");
        consensus.BIP65Height = 918684; // bab3041e8977e0dc3eeff63fe707b92bde1dd449d8efafb248c27c8264cc311a
        consensus.BIP66Height = 811879; // 7aceee012833fa8952f8835d8b1b3ae233cd6ab08fdb27a771d2bd7bdc491894
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); 
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 6048; // 75% of 8064
        consensus.nMinerConfirmationWindow = 8064; // nPowTargetTimespan / nPowTargetSpacing * 4
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0xcf824313d239eacf4b2559738021748fb22b946ad228b6a7a5938612ff0ced1b"); //155

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xd7;
        pchMessageStart[1] = 0xb7;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd0;
        nDefaultPort = 7994;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1580464050, 931820, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xdc50ba9cea4e2b2afc508ebdf796849f39d6c8d012a060a025360532c91b4ed8"));
        assert(genesis.hashMerkleRoot == uint256S("0xd1b12fb6aa246a1669ebbe7a8ba6e53a9e5f70ce1e580ab0e144fa866586fd3b"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.emplace_back("149.28.46.64", true);
        vSeeds.emplace_back("45.77.144.188", true);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,70);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,50);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,33);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x90, 0x85, 0x97, 0xDC};
        base58Prefixes[EXT_SECRET_KEY] = {0x90, 0x85, 0x81, 0x91};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            {
                {  0, uint256S("0xdc50ba9cea4e2b2afc508ebdf796849f39d6c8d012a060a025360532c91b4ed8")},
                {  1, uint256S("0x028e9007a9f5016985059fbb6f6d2abdb77d8699df82f20fdcfbe180295d51c6")},
                {  2, uint256S("0xc22fde03c3c0c03e13c6713bec31ebe3e7ca6141ae5557b795529d4ee1d5f5e8")},
                {  3, uint256S("0xd99399becf8f63cb0983fbe322b953b43fab7572a6680bc5bb31495062136f9f")},
                {  4, uint256S("0x380fb8e4de2460e8db8cbb02c51d9ae912b328075818e4a1d4050f7b4a4051cd")},
                {  5, uint256S("0x2d30dc6b143a18a204d3e7930a1343f882531079abf9c97d47185febea5b10c1")},
                {  6, uint256S("0xf0a73320b6c02da783557115729739cb9863393d1eeac0da63fd2da964b32c2f")},
                {  7, uint256S("0x1bffb0be7c0957159ab62a8661204d11ce421d5b98e016d8e38e680bc740ab9e")},
                {  8, uint256S("0x4531b56190795e212346ec373c40fb1c91e2bead0e78e9450d851fcb9873457f")},
                {  9, uint256S("0xfb94d9c1cbcf4a5845be823eb7d5aba8101f459795342eba5d91caf292030c9e")},
                {  10, uint256S("0xefb5a83383b7ff35e4d380fe298e6810f7fe43e93fe81332b36ac7574dd4c4dc")},
                {  11, uint256S("0xba069fd6ca8a28910265d49965bc71078387c0830e8e1e981009ffa6e77f2500")},
                {  12, uint256S("0xff3d0c569619a316ca06aa5c1ddb31217c433bc61d0a2004f3456825e8948b6c")},
                {  13, uint256S("0xacaf8c047bddb71a430973c2d299a2390c34a05f7d737471d01ffeac911fe753")},
                {  14, uint256S("0x8e98f371356152e79754378edffa5ccf63987733ad83b2e236ffde072f02cc9f")},
                {  15, uint256S("0xb550a532b9866ad6f1114a4fa6648adfa5bb96e4e7f82593549dd053eccae452")},
                {  16, uint256S("0xdd381af8d0fcec80e9dd74b63f6be0c1dadcff3dca569fc2686ce2bb1b5f82b5")},
                {  17, uint256S("0xebc8557d770606a34c4f5cb3663e998ccde0e3c6c8cce3432fe481e262d501ef")},
                {  18, uint256S("0x5944271119d2d6c53ce5da7a38a128a18f0af0d1574cb8381722bed1805e4c4b")},
                {  19, uint256S("0x1ddcf83e41dd526fae666fe8bae114475d05bf11236ec96b5a851b336961a7a8")},
                {  20, uint256S("0x06fb8168c1e393a387238bb666a2881d6c3817cee9cc9233cd5c663570e954ad")},
                {  21, uint256S("0xf87a6e4bb74baa1ce70d5916c3690ea2ff551c8a3b486efd1caa38c7e28ed012")},
                {  22, uint256S("0x33026a2643a28a02ed9410cd5318e70372917c78d516bc8faa42a71466715559")},
                {  23, uint256S("0x28ca6b00397fcc92cf53a9ba19a79775af7318a3b2b189b5e044715e2f390e54")},
                {  24, uint256S("0x82bdb1c6be341e086fe7b2cf5983368180614285bd891888a2811fb53d32f5ca")},
                {  25, uint256S("0x263dde0b9f5409a8e2abe12b84b3dff3f3bd4582a240836b80f5ec6fdd86ca80")},
                {  26, uint256S("0xa831a266dbc931e57556fa09f2210edc82eb959200be0fef8fa089a831c6ae61")},
                {  27, uint256S("0x54ff875f536e7f44e355f66af0d45f88b5bd8b739d8fb3c4e747db32625f6dfa")},
                {  28, uint256S("0xe6ac1dbea2d7acf96c9a5872a6be9d2eade4c9d2343a38f972cf1880c4a58ea6")},
                {  29, uint256S("0x5d6f2c9602028714cd26729ed604af46cf033da820ee4fb961ee1ad818bab8fc")},
                {  30, uint256S("0x8319de5caf72ecf3a8480c442123265e5b5495bbe1388989b5ea7ec7c11543dd")},
                {  31, uint256S("0x7a982ae11f320e1191e946e7132280c3ac2faba90822861b284249199f3562e6")},
                {  32, uint256S("0x857d65454d064e4824ef4efefaeed744ceadce41329929339353e9d572411af6")},
                {  33, uint256S("0xfbd58a26ccd8102b2503e87a15f21e55b6b19e61da31da20f5b35344d1c58e9f")},
                {  34, uint256S("0x7e0690c692e6ddf08608f9356327ae6a6bc9298426e86a6c6a300d980acd6b3d")},
                {  35, uint256S("0xb7004ab0aced698dbf82bcca4ce07f19ad6a7c041f4b92e8e5f9440db0ce37a7")},
                {  36, uint256S("0xf50f1a229ab45acd00ed3f1cba85a38a8e5a68437461360f8c34a7d8ef13af3f")},
                {  37, uint256S("0xbebb0a6e18ee25b55994dbcbc2bc9cb48364d7ef76228ea9f4f04e01999a27d8")},
                {  38, uint256S("0xc5771e854efb9a6095cab833f9cc8e2e5820c48f80f18430896bd7424c4e758d")},
                {  39, uint256S("0x1b25050dd995b463a3a31ca66c0d51bdd16ba8c03de706a31de855b91b439fd7")},
                {  40, uint256S("0x538c8171d18b27a25757f6e44852e41f52e2e87e8d2e40e745694fb33fc08987")},
                {  41, uint256S("0xe8b9a97682cf4d29415597aa1b1e4f3e38916fc37018b2afb4357bb03d05e664")},
                {  42, uint256S("0x53e3546dddc6ce9ab20779e4846a5b9196a11c050b37da9dae56e8fc9b164bb7")},
                {  43, uint256S("0xc782f3c8fc60e5c3c1e66e093a86fc1b611442b6944bdf1b03dd3b87be2a2dde")},
                {  44, uint256S("0x278a19464685620ffa5c63167a19a922b3fa9d9940058c9d2553db1be05b5fb7")},
                {  45, uint256S("0x5dfa0ac3e0be412fe02dc7cc2e0db00ed5671ad912097917e269dbf90de628d5")},
                {  46, uint256S("0xfe87a67eaaf66099a4a94cb24970c37867243d5a76c1bae53a0f73494b7df195")},
                {  47, uint256S("0x88222f57730fd89f787ac7d567c3a8977d31dcb4cab5731cd80458f6690ea476")},
                {  48, uint256S("0x7d80bbd937b256b3116549410db8b97caa4d29136ff4f7bedb5f721c8f82bb52")},
                {  49, uint256S("0xc19a70dd4ab5041742884578cbcc76b015e094aa9bb294741740bbdba4ec20f6")},
                {  50, uint256S("0xcc786fb813d02f3ba48992076b3c141980d9c1901897166df61f52dbfd37a34a")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 59c9b9d3fec105bdc716d84caa7579503d5b05b73618d0bf2d5fa639f780a011 (height 1353397).
            1580464050, // * UNIX timestamp of last known number of transactions
            0,  // * total number of transactions between genesis and that timestamp
                    //   (the tx=... number in the SetBestChain debug.log lines)
            0     // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.BIP34Height = 76;
        consensus.BIP34Hash = uint256S("8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573");
        consensus.BIP65Height = 76; // 8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573
        consensus.BIP66Height = 76; // 8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000007d006a402163e");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0xa0afbded94d4be233e191525dc2d467af5c7eab3143c852c3cd549831022aad6"); //343833

        pchMessageStart[0] = 0xfd;
        pchMessageStart[1] = 0xd2;
        pchMessageStart[2] = 0xc8;
        pchMessageStart[3] = 0xf1;
        nDefaultPort = 17994;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1486949366, 293345, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0"));
        assert(genesis.hashMerkleRoot == uint256S("0x97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed.herbsterstools.com", true);
        vSeeds.emplace_back("seed-b.herbsters.loshan.co.uk", true);
        vSeeds.emplace_back("dnsseed-testnet.thrasher.io", true);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            {
                {2056, uint256S("17748a31ba97afdc9a4f86837a39d287e3e7c7290a08a1d816c5969c78a83289")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block a0afbded94d4be233e191525dc2d467af5c7eab3143c852c3cd549831022aad6 (height 343833)
            1516406749,
            794057,
            0.01
        };

    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 27994;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 0, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9"));
        assert(genesis.hashMerkleRoot == uint256S("0x97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true; 

        checkpointData = (CCheckpointData) {
            {
                {0, uint256S("530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
