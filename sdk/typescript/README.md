# @microai/paygate-sdk

TypeScript SDK for MicroAI-Paygate with EIP-712 signing and cryptographic receipt verification.

## Features

- ✅ **Auto-handling of 402 Payment Required flow**
- ✅ **EIP-712 signature generation** via ethers.js
- ✅ **Receipt verification** compatible with Go's crypto.Sign
- ✅ **TypeScript native** with full type definitions
- ✅ **Works with any wallet** (MetaMask, Privy, WalletConnect, etc.)
- ✅ **ESM and CJS** dual package support

## Installation

```bash
npm install @microai/paygate-sdk ethers
```

## Quick Start

```typescript
import { PaygateClient } from '@microai/paygate-sdk';
import { ethers } from 'ethers';

// Connect to user's wallet
const provider = new ethers.BrowserProvider(window.ethereum);
const signer = await provider.getSigner();

// Create client
const client = new PaygateClient('https://paygate.example.com', signer);

// Make a request (SDK handles payment automatically)
const { data, receipt } = await client.request('/api/ai/summarize', {
  text: 'Long article to summarize...'
});

console.log('Summary:', data.result);
console.log('Receipt ID:', receipt.receipt.id);
```

## Usage

###  Browser with MetaMask

```typescript
import { PaygateClient } from '@microai/paygate-sdk';
import { ethers } from 'ethers';

// Request wallet connection
await window.ethereum.request({ method: 'eth_requestAccounts' });

// Create provider and signer
const provider = new ethers.BrowserProvider(window.ethereum);
const signer = await provider.getSigner();

// Initialize client
const client = new PaygateClient('https://paygate.example.com', signer);

// Use the client
const response = await client.request('/api/ai/summarize', {
  text: 'Article text here...'
});
```

### Node.js with Private Key

```typescript
import { PaygateClient } from '@microai/paygate-sdk';
import { ethers } from 'ethers';

// Create signer from private key
const provider = new ethers.JsonRpcProvider('https://base-mainnet.g.alchemy.com/v2/...');
const signer = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

// Initialize client
const client = new PaygateClient('https://paygate.example.com', signer);

// Make requests
const response = await client.request('/api/ai/summarize', {
  text: 'Article text...'
});
```

### With Privy

```typescript
import { usePrivy } from '@privy-io/react-auth';
import { PaygateClient } from '@microai/paygate-sdk';
import { ethers } from 'ethers';

function MyComponent() {
  const { authenticated, user } = usePrivy();

  const makeRequest = async () => {
    const provider = await user.wallet.getEthersProvider();
    const signer = provider.getSigner();

    const client = new PaygateClient('https://paygate.example.com', signer);
    
    const response = await client.request('/api/ai/summarize', {
      text: 'Article...'
    });
  };

  return <button onClick={makeRequest}>Summarize</button>;
}
```

## API Reference

### `PaygateClient`

#### Constructor

```typescript
new PaygateClient(
  serverUrl: string,
  signer: ethers.Signer,
  options?: {
    autoVerifyReceipts?: boolean; // default: true
    timeout?: number;             // default: 30000ms
  }
)
```

#### Methods

**`request<T>(endpoint: string, body: any, options?: RequestOptions): Promise<PaygateResponse<T>>`**

Makes an API request with automatic 402 payment handling.

```typescript
const { data, receipt } = await client.request('/api/ai/summarize', {
  text: 'Article to summarize'
});
```

**`signPayment(context: PaymentContext): Promise<string>`**

Signs a payment context using EIP-712.

```typescript
const signature = await client.signPayment({
  recipient: '0x...',
  token: 'USDC',
  amount: '0.001',
  nonce: 'abc123',
  chainId: 8453
});
```

**`verifyReceipt(receipt: SignedReceipt): Promise<boolean>`**

Verifies a cryptographic receipt.

```typescript
const isValid = await client.verifyReceipt(response.receipt);
if (!isValid) {
  console.error('Receipt verification failed');
}
```

## Payment Flow

The SDK automatically handles the 402 Payment Required flow:

```
1. Client calls request()
2. SDK makes initial POST (no signature)
3. Gateway returns 402 + PaymentContext
4. SDK signs PaymentContext with EIP-712
5. SDK retries POST with X-402-Signature header
6. Gateway verifies signature
7. Gateway returns 200 + data + receipt
8. SDK verifies receipt
9. SDK returns { data, receipt }
```

## Receipt Verification

All receipts are automatically verified unless disabled:

```typescript
// Auto-verification enabled (default)
const client = new PaygateClient(url, signer);

// Disable auto-verification
const client = new PaygateClient(url, signer, {
  autoVerifyReceipts: false
});

// Manual verification
const isValid = await client.verifyReceipt(receipt);
```

## Error Handling

```typescript
try {
  const response = await client.request('/api/ai/summarize', { text: '...' });
} catch (error) {
  if (error.message.includes('402')) {
    console.error('Payment failed:', error);
  } else if (error.message.includes('verification failed')) {
    console.error('Receipt verification failed');
  } else {
    console.error('Request error:', error);
  }
}
```

## TypeScript Types

```typescript
import type {
  PaymentContext,
  SignedReceipt,
  PaygateResponse,
  RequestOptions,
} from '@microai/paygate-sdk';
```

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Type check
npm run type-check
```

## License

MIT

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](../../CONTRIBUTING.md) for details.
