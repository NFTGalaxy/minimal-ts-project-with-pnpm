import type { NextApiRequest, NextApiResponse } from 'next';
import {
  prepare,
  credential,
  evm,
  credType,
  errors,
  user,
  issuer,
  babyzk,
  utils,
  babyzkTypes,
} from '@galxe-identity-protocol/sdk';
import { ethers } from 'ethers';

const unwrap = errors.unwrap;
const MAINNET_RPC = 'https://rpc.ankr.com/eth';
const provider = new ethers.JsonRpcProvider(MAINNET_RPC);
const dummyIssuerEvmAddr = '0x15f4a32c40152a0f48E61B7aed455702D1Ea725e';

async function issuingProcess(userEvmAddr: string, userIdc: bigint) {
  const typeSpec = credType.primitiveTypes.scalar;
  const tp = unwrap(credType.createTypeFromSpec(typeSpec));
  const txCount = await provider.getTransactionCount(userEvmAddr);
  const contextID = credential.computeContextID('Number of transactions');
  const newCred = unwrap(
    credential.Credential.create(
      {
        type: tp,
        contextID: contextID,
        userID: BigInt(userEvmAddr),
      },
      {
        val: BigInt(txCount).toString(),
      }
    )
  );
  newCred.attachments['creativity'] = 'uncountable';
  const issuerID = BigInt(dummyIssuerEvmAddr);
  const issuerChainID = BigInt(1);
  const dummyKey = utils.decodeFromHex('0xfd60ceb442aca7f74d2e56c1f0e93507798e8a6e02c4cd1a5585a36167fa7b03');
  const issuerPk = dummyKey;
  const myIssuer = new issuer.BabyzkIssuer(issuerPk, issuerID, issuerChainID);
  myIssuer.sign(newCred, {
    sigID: BigInt(100),
    expiredAt: BigInt(Math.ceil(new Date().getTime() / 1000) + 7 * 24 * 60 * 60),
    identityCommitment: userIdc,
  });
  return newCred;
}

async function proofGenProcess(myCred: credential.Credential, u: user.User) {
  const externalNullifier = utils.computeExternalNullifier("Galxe Identity Protocol tutorial's verification");
  const proofGenGadgets = await user.User.fetchProofGenGadgetsByTypeID(myCred.header.type, provider);
  const expiredAtLowerBound = BigInt(Math.ceil(new Date().getTime() / 1000) + 3 * 24 * 60 * 60);
  const equalCheckId = BigInt(0);
  const pseudonym = BigInt('0xdeadbeef');
  const proof = await u.genBabyzkProofWithQuery(
    u.getIdentityCommitment('evm')!,
    myCred,
    proofGenGadgets,
    `
    {
      "conditions": [
        {
          "identifier": "val",
          "operation": "IN",
          "value": {
            "from": "500",
            "to": "5000"
          }
        }
      ],
      "options": {
        "expiredAtLowerBound": "${expiredAtLowerBound}",
        "externalNullifier": "${externalNullifier}",
        "equalCheckId": "${equalCheckId}",
        "pseudonym": "${pseudonym}"
      }
    }
    `
  );
  return proof;
}

async function verifyByCallingEvmStatefulVerifier(proof: babyzkTypes.WholeProof): Promise<boolean> {
  const expectedContextID = credential.computeContextID('Number of transactions');
  const expectedIssuerID = BigInt(dummyIssuerEvmAddr);
  const expectedTypeID = credType.primitiveTypes.scalar.type_id;
  const statefulVerifier = evm.v1.createBabyzkStatefulVerifier({
    signerOrProvider: provider,
  });
  const statefulVerifierResult = await statefulVerifier.verifyWholeProofFull(
    expectedTypeID,
    expectedContextID,
    expectedIssuerID,
    proof
  );
  if (statefulVerifierResult !== evm.VerifyResult.OK) {
    console.error('Proof verification failed, reason: ', evm.verifyResultToString(statefulVerifierResult));
  } else {
    console.log('On-chain stateful proof verification is successful.');
  }
  return true;
}

async function verifyByOffchain(proof: babyzkTypes.WholeProof): Promise<boolean> {
  const expectedContextID = credential.computeContextID('Number of transactions');
  const expectedIssuerID = BigInt(dummyIssuerEvmAddr);
  const expectedTypeID = credType.primitiveTypes.scalar.type_id;
  const tpRegistry = evm.v1.createTypeRegistry({
    signerOrProvider: provider,
  });
  const verifier = await tpRegistry.getVerifier(expectedTypeID, credential.VerificationStackEnum.BabyZK);
  const vKey = await verifier.getVerificationKeysRaw();
  const verifyResult = await babyzk.verifyProofRaw(vKey, proof);
  const IssuerRegistry = evm.v1.createIssuerRegistry({
    signerOrProvider: provider,
  });
  const pubkeyId = babyzk.defaultPublicSignalGetter(credential.IntrinsicPublicSignal.KeyId, proof);
  if (pubkeyId === undefined) {
    return false;
  }
  const isActive = await IssuerRegistry.isPublicKeyActiveForStack(
    expectedIssuerID,
    pubkeyId,
    credential.VerificationStackEnum.BabyZK
  );
  if (!isActive) {
    return false;
  }
  const contextId = babyzk.defaultPublicSignalGetter(credential.IntrinsicPublicSignal.Context, proof);
  if (contextId === undefined) {
    return false;
  }
  if (contextId !== expectedContextID) {
    return false;
  }
  const expiredAtLb = babyzk.defaultPublicSignalGetter(credential.IntrinsicPublicSignal.ExpirationLb, proof);
  if (expiredAtLb === undefined) {
    return false;
  }
  if (expiredAtLb < BigInt(Math.ceil(new Date().getTime() / 1000))) {
    return false;
  }
  return true;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await prepare();
  const u = new user.User();
  const evmIdSlice = u.createNewIdentitySlice('evm');
  const userIdc = user.User.computeIdentityCommitment(evmIdSlice);
  const userEvmAddr = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
  const myCred = await issuingProcess(userEvmAddr, userIdc);
  const proof = await proofGenProcess(myCred, u);
  const onChainResult = await verifyByCallingEvmStatefulVerifier(proof);
  const offChainResult = await verifyByOffchain(proof);
  res.status(200).json({ onChainResult, offChainResult });
}
