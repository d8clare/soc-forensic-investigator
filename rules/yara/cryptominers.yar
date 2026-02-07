/*
    Cryptominer and Cryptojacking Detection
*/

rule Cryptominer_XMRig {
    meta:
        description = "Detects XMRig cryptocurrency miner"
        severity = "high"
        mitre = "T1496"
    strings:
        $s1 = "xmrig" ascii wide nocase
        $s2 = "stratum+tcp://" ascii wide nocase
        $s3 = "stratum+ssl://" ascii wide nocase
        $s4 = "randomx" ascii wide nocase
        $s5 = "cryptonight" ascii wide nocase
        $s6 = "\"algo\"" ascii wide
        $s7 = "\"pool\"" ascii wide
        $s8 = "\"wallet\"" ascii wide
    condition:
        3 of them
}

rule Cryptominer_Generic {
    meta:
        description = "Detects generic cryptocurrency miner patterns"
        severity = "high"
        mitre = "T1496"
    strings:
        $pool1 = "stratum://" ascii wide nocase
        $pool2 = "stratum+tcp://" ascii wide nocase
        $pool3 = "stratum+ssl://" ascii wide nocase
        $pool4 = "pool.minergate" ascii wide nocase
        $pool5 = "nanopool.org" ascii wide nocase
        $pool6 = "minexmr.com" ascii wide nocase
        $pool7 = "2miners.com" ascii wide nocase
        $algo1 = "cryptonight" ascii wide nocase
        $algo2 = "randomx" ascii wide nocase
        $algo3 = "ethash" ascii wide nocase
        $algo4 = "kawpow" ascii wide nocase
        $wallet = /[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii wide
    condition:
        any of ($pool*) or (any of ($algo*) and $wallet)
}

rule Cryptominer_Coinhive {
    meta:
        description = "Detects Coinhive JavaScript miner"
        severity = "high"
        mitre = "T1496"
    strings:
        $s1 = "coinhive" ascii wide nocase
        $s2 = "CoinHive" ascii wide
        $s3 = "coin-hive" ascii wide nocase
        $s4 = "authedmine" ascii wide nocase
        $s5 = "cryptoloot" ascii wide nocase
    condition:
        any of them
}

rule Cryptominer_WebMiner {
    meta:
        description = "Detects web-based cryptocurrency miners"
        severity = "medium"
        mitre = "T1496"
    strings:
        $s1 = "CryptoLoot" ascii wide nocase
        $s2 = "deepMiner" ascii wide nocase
        $s3 = "webminerpool" ascii wide nocase
        $s4 = "miner.start" ascii wide nocase
        $s5 = "Miner(" ascii wide
        $wasm = "WebAssembly" ascii wide
    condition:
        2 of ($s*) or (any of ($s*) and $wasm)
}

rule Cryptominer_Claymore {
    meta:
        description = "Detects Claymore miner"
        severity = "high"
        mitre = "T1496"
    strings:
        $s1 = "Claymore" ascii wide nocase
        $s2 = "ethdcrminer" ascii wide nocase
        $s3 = "EthDcrMiner" ascii wide
        $s4 = "-epool" ascii wide nocase
        $s5 = "-ewal" ascii wide nocase
    condition:
        2 of them
}

rule Cryptominer_NBMiner {
    meta:
        description = "Detects NBMiner"
        severity = "high"
        mitre = "T1496"
    strings:
        $s1 = "NBMiner" ascii wide nocase
        $s2 = "nbminer" ascii wide nocase
        $s3 = "-o stratum" ascii wide nocase
        $s4 = "-u wallet" ascii wide nocase
    condition:
        2 of them
}

rule Cryptominer_PhoenixMiner {
    meta:
        description = "Detects PhoenixMiner"
        severity = "high"
        mitre = "T1496"
    strings:
        $s1 = "PhoenixMiner" ascii wide nocase
        $s2 = "phoenixminer" ascii wide nocase
        $s3 = "-pool" ascii wide nocase
        $s4 = "-wal" ascii wide nocase
    condition:
        2 of them
}

rule Cryptominer_T_Rex {
    meta:
        description = "Detects T-Rex miner"
        severity = "high"
        mitre = "T1496"
    strings:
        $s1 = "t-rex" ascii wide nocase
        $s2 = "trex" ascii wide nocase
        $s3 = "-a kawpow" ascii wide nocase
        $s4 = "-a ethash" ascii wide nocase
    condition:
        2 of them
}
