require("dotenv").config();
const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const session = require("express-session");
const fetch = require("node-fetch").default;

const app = express();
const PORT = 3000;

const userDB = new Map();
const CERT_PROVIDERS = {
  kakao: "KakaoCertificate",
  toss: "TossCertificate",
  naver: "NaverCertificate",
  pass: "PassCertificate",
};

app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "fallback-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
  })
);

if (
  !process.env.KAKAO_CLIENT_ID ||
  !process.env.KAKAO_CLIENT_SECRET ||
  !process.env.KAKAO_REDIRECT_URI
) {
  console.error(
    "❌ .env 파일에 KAKAO_CLIENT_ID, KAKAO_CLIENT_SECRET, KAKAO_REDIRECT_URI가 필요합니다."
  );
  process.exit(1);
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "home.html"));
});

app.get("/auth/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "cert-login.html"));
});

app.get("/auth/cert-confirmation", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "cert-confirmation.html"));
});

app.get("/auth/verify-user", (req, res) => {
  const { name, phone, rrn, provider } = req.query;
  if (!name || !phone || !rrn || !provider) {
    return res.status(400).send("필수 정보가 누락되었습니다.");
  }
  if (!CERT_PROVIDERS[provider]) {
    return res.status(400).send("유효하지 않은 인증서 제공자입니다.");
  }
  res.redirect(
    `/auth/cert-confirmation?name=${encodeURIComponent(
      name
    )}&phone=${encodeURIComponent(phone)}&provider=${encodeURIComponent(
      provider
    )}`
  );
});

app.post("/auth/complete-certification", (req, res) => {
  const { name, phone, provider } = req.body;
  const userId = `user_${Date.now()}`;
  let isNewUser = true;
  let existingUserId = null;

  for (const [id, user] of userDB.entries()) {
    if (user.phone === phone) {
      isNewUser = false;
      existingUserId = id;
      break;
    }
  }

  if (isNewUser) {
    const params = new URLSearchParams({
      userId: userId,
      name: name,
      phone: phone,
      certProvider: CERT_PROVIDERS[provider],
    });
    res.json({
      success: true,
      isNewUser: true,
      redirectUrl: `/signup.html?${params.toString()}`,
    });
  } else {
    const user = userDB.get(existingUserId);
    user.lastLogin = new Date();
    user.lastCertProvider = CERT_PROVIDERS[provider];
    userDB.set(existingUserId, user);
    req.session.userId = existingUserId;
    res.json({
      success: true,
      isNewUser: false,
      redirectUrl: "/success.html",
    });
  }
});

app.post("/auth/complete-signup", (req, res) => {
  const { userId, nickname, email, phone, name, certProvider } = req.body;
  const newUser = {
    id: userId,
    name: name || nickname,
    nickname: nickname,
    email: email,
    phone: phone,
    certProvider: certProvider,
    isRegistered: true,
    registeredAt: new Date(),
    lastLogin: new Date(),
  };
  userDB.set(userId, newUser);
  req.session.userId = userId;
  res.json({ success: true });
});

app.get("/auth/kakao", async (req, res) => {
  if (req.session.kakaoAccessToken) {
    try {
      const scopesResponse = await fetch(
        "https://kapi.kakao.com/v2/user/scopes",
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${req.session.kakaoAccessToken}`,
          },
        }
      );
      const scopesData = await scopesResponse.json();
      console.log("📌 현재 동의 상태:", scopesData);

      if (scopesData.scopes && scopesData.scopes.length > 0) {
        await fetch("https://kapi.kakao.com/v2/user/revoke/scopes", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${req.session.kakaoAccessToken}`,
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            scopes: JSON.stringify([
              "profile_nickname",
              "profile_image",
              "talk_message",
            ]),
          }),
        });
        console.log("📌 동의 철회 성공");
      }

      await fetch("https://kapi.kakao.com/v1/user/logout", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${req.session.kakaoAccessToken}`,
        },
      });
      console.log("📌 기존 카카오 세션 로그아웃 성공");
    } catch (error) {
      console.error("❌ 카카오 로그아웃/동의 철회 실패:", error.message);
    }
    delete req.session.kakaoAccessToken;
  }

  const kakaoAuthUrl = `https://kauth.kakao.com/oauth/authorize?client_id=${
    process.env.KAKAO_CLIENT_ID
  }&redirect_uri=${encodeURIComponent(
    process.env.KAKAO_REDIRECT_URI
  )}&response_type=code&scope=profile_nickname,profile_image,talk_message&prompt=login,consent`;
  console.log("📌 카카오 로그인 시작:", kakaoAuthUrl);
  res.redirect(kakaoAuthUrl);
});

app.get("/auth/kakao/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) {
    console.error("❌ 인증 코드 누락");
    return res.status(400).json({ error: "인증 코드가 없습니다." });
  }
  console.log("📌 인증 코드:", code);

  try {
    const tokenResponse = await fetch("https://kauth.kakao.com/oauth/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: process.env.KAKAO_CLIENT_ID,
        client_secret: process.env.KAKAO_CLIENT_SECRET,
        redirect_uri: process.env.KAKAO_REDIRECT_URI,
        code: code,
      }),
    });

    const tokenData = await tokenResponse.json();
    if (tokenData.error) {
      console.error("❌ 토큰 요청 실패:", tokenData);
      return res.status(400).json({
        error: "토큰 요청 실패",
        details: tokenData.error_description,
      });
    }
    console.log("📌 토큰 요청 성공");

    const userResponse = await fetch("https://kapi.kakao.com/v2/user/me", {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });

    const userData = await userResponse.json();
    if (userData.error) {
      console.error("❌ 사용자 정보 요청 실패:", userData);
      return res.status(400).json({
        error: "사용자 정보 요청 실패",
        details: userData.error_description,
      });
    }
    console.log("📌 사용자 정보:", userData);

    const kakaoId = userData.id;
    const nickname = userData.kakao_account?.profile?.nickname || "익명";
    const profileImage =
      userData.kakao_account?.profile?.profile_image_url || "";

    let userId = null;
    for (const [id, user] of userDB.entries()) {
      if (user.kakaoId === kakaoId) {
        userId = id;
        break;
      }
    }

    if (!userId) {
      userId = `kakao_${kakaoId}`;
      userDB.set(userId, {
        id: userId,
        kakaoId: kakaoId,
        name: nickname,
        nickname: nickname,
        profileImage: profileImage,
        certProvider: "KakaoOAuth",
        isRegistered: true,
        registeredAt: new Date(),
        lastLogin: new Date(),
        hasTalkMessage: userData.kakao_account?.has_talk_message || false,
      });
      console.log("📌 신규 유저:", nickname);
    } else {
      const user = userDB.get(userId);
      user.lastLogin = new Date();
      user.nickname = nickname;
      user.profileImage = profileImage;
      user.hasTalkMessage = userData.kakao_account?.has_talk_message || false;
      userDB.set(userId, user);
      console.log("📌 기존 유저:", nickname);
    }

    req.session.userId = userId;
    req.session.kakaoAccessToken = tokenData.access_token;
    res.redirect("/home");
  } catch (error) {
    console.error("❌ 카카오 로그인 오류:", error.message, error.stack);
    res.status(500).json({ error: "서버 오류", details: error.message });
  }
});

app.post("/auth/kakao/unlink", async (req, res) => {
  const userId = req.session.userId;
  if (!userId || !userDB.has(userId)) {
    return res.status(401).json({ error: "로그인하지 않았습니다." });
  }

  const user = userDB.get(userId);
  if (!user.kakaoId) {
    return res
      .status(400)
      .json({ error: "카카오 계정이 연결되지 않았습니다." });
  }

  try {
    const accessToken = req.session.kakaoAccessToken;
    if (accessToken) {
      await fetch("https://kapi.kakao.com/v1/user/unlink", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
    }

    user.kakaoId = null;
    user.hasTalkMessage = false;
    user.profileImage = "";
    user.nickname = user.name || "익명";
    userDB.set(userId, user);
    delete req.session.kakaoAccessToken;

    console.log("📌 카카오 연결 해제:", userId);
    res.json({ success: true });
  } catch (error) {
    console.error("❌ 연결 해제 오류:", error.message);
    res.status(500).json({ error: "연결 해제 실패", details: error.message });
  }
});

app.get("/home", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "home.html"));
});

app.get("/sns-upload", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "home.html"));
});

app.get("/data-management", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "data-management.html"));
});

app.get("/api/user-info", (req, res) => {
  const userId = req.session.userId;
  if (userId && userDB.has(userId)) {
    res.json(userDB.get(userId));
  } else {
    res.status(401).json({ error: "로그인하지 않았습니다." });
  }
});

app.get("/api/kakao/messages", async (req, res) => {
  const userId = req.session.userId;
  if (!userId || !userDB.has(userId)) {
    return res.status(401).json({ error: "로그인하지 않았습니다." });
  }
  const user = userDB.get(userId);
  if (!user.hasTalkMessage) {
    return res.json({ messages: [] });
  }
  const mockMessages = [
    { id: "msg1", content: "안녕하세요!", timestamp: new Date().toISOString() },
    {
      id: "msg2",
      content: "만나서 반갑습니다.",
      timestamp: new Date().toISOString(),
    },
  ];
  res.json({ messages: mockMessages });
});

app.post("/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ success: false });
    }
    res.json({ success: true });
  });
});

app.get("/success", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "success.html"));
});

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "signup.html"));
});

app.listen(PORT, () => {
  console.log(`✅ 서버 실행 중: http://localhost:${PORT}`);
});

app.post("/api/invite-agent", (req, res) => {
  const agent = req.body;
  // TODO: 실제 이메일 발송 로직 추가 (예: nodemailer 사용)
  console.log(
    `대리인 초대 이메일 발송: ${agent.email}, 링크: ${agent.inviteLink}`
  );
  res.json({ success: true });
});

app.post("/api/resend-invite", (req, res) => {
  const { agentId, email } = req.body;
  // TODO: 실제 이메일 재발송 로직 추가
  console.log(`대리인 초대 이메일 재발송: ${email}`);
  res.json({ success: true });
});

app.post("/api/save-data", (req, res) => {
  const { userId, transferDataList, deleteDataList } = req.body;
  // TODO: 데이터베이스에 저장
  res.json({ success: true });
});

app.get("/api/agents", (req, res) => {
  // TODO: 대리인 목록 반환
  res.json(agents);
});
