# Cash App Payment Circuits

When a seller places a sell order, they will post a commitment to their username. These usernames are unique, and are used to verify that the buyer paid 
the correct person. A buyer will first place a claim on the Zephyr orderbook contract, the buyer will then send the Cash App payment with the correct note (correspinding
to the claim) to the correct username. In some cases, a payment can go through and get reverted by Cash App a few minutes larer. In such cases the buyer
will recieve the confirmation email and get their funds back, therefore, it's important for the seller to be able to dispute the transaction and prove that
the payment was reverted. This is why the Cash App verifier has a one hour dispute period during which a seller can submit a zero-knowledge proof of a "Payment
Failed" email corresponding to the transaction - which is identified by the unique transaction identifier. The repository contains the Zero-Knowledge circuits for both
proof of Cash App payments, and proof of Cash App Payment Failed emails.

## Constraints

| Constraints        | Templating | Hashing & Signature | Total |
|--------------------|-------|---------|------------|
| Cash App Payment   | 3,114,241 | 14,920,618 | 18,034,859 |
| Payment Fail       | 473,542 |15,375,916 | 15,849,458 |


## General Circuit Paradigm

We build our circuits with two intentions in mind:
- (**Completeness** & **Soundness**) Given the current Cash App email template, honest provers' emails should always generate valid proofs and malicious provers should never be able to generate a valid proof.
- (**Safeguard**) Given the slightest change in the email template by Cash App, the proof should always fail. We made this design choice because it is impossible to predict was potential exploits could come up if Cash App changed their template therefore we would rather all proofs fail and we create a new circuit adapted for the new template.

Given this, we detail that the following parts of the circuit are done for completeness and soundness:
- Verifying the pair of RSA signatures.
- Computing the hash of the body.
- Extracting the body hash from the header and checking equality with the body hash and between headers.
Extracting the relevant information from the body.

The following parts are done as a safeguard:
- Constraining all the fix html sections of the Cash App body.
- Extracting the name and amount from the subject and checking against the values extracted from the body.

## Zephyr-Cash-App Licensing

Select components of Zephyr-Cash-App, which are marked with "SPDX-License-Identifier: BUSL-1.1", were launched under a Business Source License 1.1 (BUSL 1.1).

The license limits use of the Zephyr source code in a commercial or production setting until January 1st, 2026. After this, the license will convert to a general public license. This means anyone can fork the code for their own use — as long as it is kept open source.

In addition, certain parts of Zephyr-Cash-App are derived from other sources and are separately licensed under the GNU General Public License (GPL-3.0-only). These components are explicitly marked with "SPDX-License-Identifier: GPL-3.0-only" and are subject to the terms of the GNU GPL. The full text of the GPL license can be found in the LICENSE-GPL file in the root directory of this project.