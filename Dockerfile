# 1) Build the React SPA into the API's wwwroot. 2) Publish the API. 3) Run on the ASP.NET Core runtime as non-root.
FROM node:24-slim AS web
WORKDIR /repo/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY global.json Directory.Build.props Directory.Packages.props .editorconfig ./
COPY src/ src/
COPY --from=web /repo/src/Auth.Api/wwwroot src/Auth.Api/wwwroot
RUN dotnet publish src/Auth.Api/Auth.Api.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app ./
RUN mkdir -p /app/data && chown "$APP_UID" /app/data
USER $APP_UID
ENV ASPNETCORE_HTTP_PORTS=8080 \
    ConnectionStrings__Auth="Data Source=/app/data/auth.db" \
    Auth__SigningKeyPath=/app/data/signing-key.pem
EXPOSE 8080
ENTRYPOINT ["dotnet", "Auth.Api.dll"]
