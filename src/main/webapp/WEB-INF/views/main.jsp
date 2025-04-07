<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<html>
<head>
    <title>Main Page</title>
    <style>
        body { font-family: sans-serif; padding: 20px; }
        a { margin-right: 15px; }
        #refresh-status { margin-top: 20px; font-style: italic; color: #555; }
    </style>
</head>
<body>
    <h1>Welcome, <c:out value="${username}"/>!</h1>
    <p>This is the main application page.</p>

    <a href="<c:url value='/hello'/>">Access Protected Resource (/hello)</a>

    <form action="<c:url value='/logout'/>" method="post" style="display: inline;">
        <button type="submit">Logout</button>
    </form>

    <div id="refresh-status"></div>

    <script>
        // Access token 만료 시간 (밀리초 단위, 서버에서 전달받음)
        const accessTokenExpiryMs = Number('${accessTokenExpiryMs}'); // e.g., 3600000 (1 hour)
        // 안전 마진 (만료되기 5분 전에 갱신 시도)
        const refreshMarginMs = 5 * 60 * 1000; // 5 minutes in ms
        // 실제 갱신 주기
        const refreshIntervalMs = accessTokenExpiryMs - refreshMarginMs;

        const statusDiv = document.getElementById('refresh-status');

        function scheduleTokenRefresh() {
            if (refreshIntervalMs > 0) {
                console.log(`Scheduling token refresh check in ${refreshIntervalMs / 1000 / 60} minutes.`);
                setTimeout(refreshToken, refreshIntervalMs);
            } else {
                // 만료 시간이 너무 짧으면 즉시 또는 매우 자주 갱신 시도 (조정 필요)
                 console.warn('Access token expiry is too short for scheduled refresh margin. Refreshing more frequently or immediately.');
                 // Example: Refresh every half of the expiry time if margin is too large
                 const shortInterval = accessTokenExpiryMs / 2;
                 if (shortInterval > 10000) { // Avoid too frequent refreshes (e.g., > 10 seconds)
                    console.log(`Refreshing in ${shortInterval / 1000} seconds.`);
                    setTimeout(refreshToken, shortInterval);
                 } else {
                    console.log('Expiry too short, attempting refresh now.');
                    refreshToken(); // Attempt refresh immediately if interval is too small
                 }
            }
        }

        async function refreshToken() {
            statusDiv.textContent = 'Attempting token refresh...';
            console.log('Attempting to refresh token...');
            try {
                const response = await fetch('/api/token/refresh', {
                    method: 'POST',
                    headers: {
                        // 쿠키는 브라우저가 자동으로 전송하므로 헤더에 명시적으로 추가할 필요 없음
                        'Content-Type': 'application/json' // 필요시 Content-Type 지정 (이 엔드포인트는 body가 없어도 됨)
                    }
                    // body는 필요 없음
                });

                if (response.ok) {
                    // 성공 시, 새 Access Token 쿠키가 자동으로 설정됨
                    statusDiv.textContent = 'Token refreshed successfully at ' + new Date().toLocaleTimeString();
                    console.log('Token refreshed successfully.');
                    // 다음 갱신 스케줄링
                    scheduleTokenRefresh();
                } else {
                    // 실패 시 (401 Unauthorized 등) - Refresh Token 만료 또는 무효
                    statusDiv.textContent = 'Failed to refresh token. Redirecting to login.';
                    console.error('Failed to refresh token. Status:', response.status);
                    // 로그인 페이지로 리다이렉트
                    window.location.href = '/login?sessionExpired=true';
                }
            } catch (error) {
                statusDiv.textContent = 'Error during token refresh. Check console.';
                console.error('Network or other error during token refresh:', error);
                 // 네트워크 오류 등의 경우, 잠시 후 재시도 로직을 추가할 수도 있음
                 // 예: setTimeout(refreshToken, 30000); // 30초 후 재시도
                 // 여기서는 간단하게 실패 처리
                 // 필요하다면 로그인 페이지로 리다이렉트
                 // window.location.href = '/login?error=refreshFailed';
            }
        }

        // 페이지 로드 시 첫 갱신 스케줄링 시작
        scheduleTokenRefresh();
        statusDiv.textContent = 'Token refresh scheduler initialized.';

    </script>
</body>
</html>