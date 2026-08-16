// Money is always stored and calculated in sen (RM cents) as integers,
// never as decimals -- this avoids floating-point rounding bugs that show
// up in POS systems handling money as 12.50 instead of 1250. These two
// functions are the only place conversion should happen: right at the
// boundary where a human types or reads a price.

export function ringgitToSen(value) {
  const num = Number(value);
  if (Number.isNaN(num)) return null;
  return Math.round(num * 100);
}

export function senToRinggit(sen) {
  return (sen / 100).toFixed(2);
}