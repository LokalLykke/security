lazy val root = (project in file("."))
  .settings(
    scalaVersion := "2.13.5",
    organization := "lokallykke.dk",
    name := """lokallykke-security""",
    libraryDependencies ++= Seq(
      ws,
      guice
    )
  )
  .enablePlugins(PlayScala)
  .disablePlugins(PlayLayoutPlugin)
  
  

