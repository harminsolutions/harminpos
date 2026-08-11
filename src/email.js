export async function sendOTPEmail(env, toEmail, otp) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: "HarminPOS <noreply@mail.harminsolutions.com>",
      to: [toEmail],
      subject: "Your HarminPOS verification code",
      text: `Your verification code is ${otp}. It expires in 10 minutes.`,
    }),
  });
  return res.ok;
}