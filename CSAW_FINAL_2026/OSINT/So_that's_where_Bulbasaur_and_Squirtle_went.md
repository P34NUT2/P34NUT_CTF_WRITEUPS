# CSAW_Finals_2026

# So that's where Bulbasaur and Squirtle went

## OSINT

## Description
Find the city to translate this key:
0a304f1d1c259befed1b6b1e001a012a590711033b59161b1a67591a070a6b161b1c0a3959091b1d260a43541b23181b541e3e161b114f2610081c1b6b1b0a541a381c090103675901151d391618540b240e015416240c1d541c2e181d1707

## Files
> image.jpg
<img width="1179" height="1601" alt="image" src="https://github.com/user-attachments/assets/fe4f6f32-aa3c-48b6-bac5-ef486de4e354" />

---

## Analysis

The first thing that stands out is the ciphertext. It's in hex, and the description says we need a city to "translate" it, so the idea is to decode it from hex and XOR it with the city name as the key.

To find the city, I ran the image through Google reverse image search and it turned out to be a `Pokémon Center` (the Bulbasaur and Squirtle keychain plushies give it away). Pokémon Centers are mostly in Japan, so I looked them up on Google Maps and tried the cities one by one as the key.

```
Key: Kyoto

Decrypted text:
AI isn’t gonna help you, use other forms, that quote might be useful, narrow down your search
```

So the decrypted text isn't the flag, it's a hint. And yeah, AI wasn't much help here (I tested a bit with Claude and Gemini and they didn't get anywhere). The useful part was the bottom of the image: there's a Reddit avatar and a username that's cut off, so only the top of the letters is visible.
<img width="812" height="162" alt="image" src="https://github.com/user-attachments/assets/3995e717-0317-4187-9813-838a8d692859" />

---

## Theory

To solve this challenge, you need to understand:

- **Repeating-key XOR**: Each byte of the plaintext is XORed with a byte of the key, and the key repeats. XOR is its own inverse, so XORing the ciphertext with the same key gives back the plaintext. When the key is a short word (like a city name), you can just try candidates until the output is readable.
- **OSINT (Open Source Intelligence)**: Gathering information from public sources. Here: reverse image search, Google Maps, Reddit and Google dorks.
- **Reddit's default usernames**: When you create an account, Reddit suggests auto-generated usernames in the format `Adjective_Noun_Number`, using words from a fixed list. Knowing that pattern narrows a partial username down to a handful of candidates.
- **Glyph silhouette matching**: Even when text is cut off, the tops of the letters still tell you a lot: capitals, ascenders (`d`, `l`, `t`, `h`, `k`) and round letters (`O`, `S`, `C`) each leave a different shape. Overlaying text in the same font and size lets you check candidates letter by letter.

---

## Solution

First I looked into how Reddit generates usernames: `Adjective_Noun_Number`. So the cut-off name has to follow that order. I also checked the font Reddit uses, `IBM Plex Sans`, and with that I had enough to work with.

After thinking about it for a while, the best approach I came up with was opening Google Drawings and overlaying letters on top of the image in the same font and spacing, trying different combinations until one lined up.

<img width="869" height="225" alt="image" src="https://github.com/user-attachments/assets/2929f8d6-00be-41f6-9d03-40cf25ddfd4d" />


Once I had the name, I searched for it on Reddit and went into the account with the most karma. The phrase from the image turned out to be a running joke on the subreddit `r/MandJTV`. 
<img width="770" height="299" alt="image" src="https://github.com/user-attachments/assets/b3178159-280b-4236-a7e1-fb2f8ce01286" />


Filtering their posts by "pokemon", I found the exact post, and the flag was in the comments.
<img width="637" height="887" alt="image" src="https://github.com/user-attachments/assets/b3163716-6dd7-47e4-9470-bbd45ba5aa98" />


**MACHINE PWNED!** :)

---

## Flag
> **CSAW{p0k3m0n_talk}**

---

## How to avoid

From the poster's side, this is an opsec problem: small details add up.

- **Crop or blur usernames and UI elements** before sharing screenshots. A half-cut name is still recoverable, as this challenge shows.
- **Default auto-generated usernames are easy to reconstruct**: the format and word list are known, so a few visible pixels go a long way.
- **Unique phrases and in-jokes are searchable**: a quote from one community points straight back to it.
- **Location leaks through context**, not just metadata: a store, a sign or a product can be enough to pin down the city.

---

> **Author:** Jose Antonio Villafaña Montes de Oca
