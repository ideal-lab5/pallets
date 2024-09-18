# pallet-etf

This pallet is responsible for storing shares and commitments required to power the ETF post finality gadget. Specifically, the data contained in this pallet allows the ETF authorities to derive session keys which they use to produce thereshold BLS sigs.