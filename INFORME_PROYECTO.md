\documentclass[11pt,a4paper]{article}

% ===================== Paquetes =====================
\usepackage[spanish,es-tabla]{babel}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\geometry{margin=2.5cm}
\usepackage{titlesec}
\usepackage{enumitem}
\usepackage{hyperref}
\hypersetup{
    colorlinks=true,
    linkcolor=black,
    urlcolor=blue,
    citecolor=black,
    pdftitle={Informe de Proyecto: Sistema de Monitoreo de Integridad de Archivos (FIM)},
    pdfauthor={Estudiante de seguridad informática}
}
\usepackage{listings}
\usepackage{xcolor}
\usepackage{fancyhdr}
\usepackage{graphicx}
\usepackage{parskip}

% ===================== Estilo de código =====================
\definecolor{codebg}{RGB}{245,245,245}
\definecolor{codegray}{RGB}{110,110,110}
\definecolor{codeblue}{RGB}{0,80,160}

\lstdefinestyle{bash}{
    backgroundcolor=\color{codebg},
    basicstyle=\ttfamily\footnotesize,
    breaklines=true,
    breakatwhitespace=false,
    frame=single,
    framerule=0.3pt,
    rulecolor=\color{codegray},
    columns=fullflexible,
    keepspaces=true,
    showstringspaces=false,
    xleftmargin=4pt,
    xrightmargin=4pt,
    aboveskip=8pt,
    belowskip=8pt
}
\lstset{style=bash}

% ===================== Encabezado / pie de página =====================
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{Informe de Proyecto FIM}
\fancyhead[R]{\thepage}
\renewcommand{\headrulewidth}{0.4pt}

% ===================== Numeración de secciones =====================
\titleformat{\section}{\Large\bfseries}{\thesection.}{0.5em}{}
\titleformat{\subsection}{\large\bfseries}{\thesubsection.}{0.5em}{}
\titleformat{\subsubsection}{\normalsize\bfseries}{\thesubsubsection.}{0.5em}{}

\begin{document}

% ===================== Portada =====================
\begin{titlepage}
    \centering
    \vspace*{2cm}
    {\Huge\bfseries Sistema de Monitoreo de Integridad de Archivos (FIM)\par}
    \vspace{0.5cm}
    {\Large Prueba de Concepto (PoC FIM)\par}
    \vspace{2cm}

    \begin{tabular}{ll}
        \textbf{Área:} & Tendencias de Seguridad de la Información \\[4pt]
        \textbf{Caso de estudio:} & Ciberdefensa \\[4pt]
        \textbf{Autor:} & Estudiante de seguridad informática \\[4pt]
        \textbf{Fecha:} & 2026 \\
    \end{tabular}

    \vfill
\end{titlepage}

\tableofcontents
\newpage

% ===================== Introducción =====================
\section{Introducción}

El presente informe documenta el desarrollo de una prueba de concepto (PoC) de un sistema de monitoreo de integridad de archivos (FIM) orientado a ciberdefensa. El objetivo es detectar cambios en un entorno de laboratorio, donde Ubuntu Desktop actúa como plataforma defensora y Metasploitable2 es el objetivo monitoreado.

La idea central del proyecto es demostrar una solución defensiva que observe un objetivo comprometido de forma remota, detecte alteraciones en archivos críticos y registre incidentes sin depender de software externo. El sistema separa los roles de forma clara: Ubuntu Desktop realiza el monitoreo, Metasploitable2 es el sistema monitoreado y Kali Linux representa el atacante que modifica los archivos.

Este proyecto aborda elementos clave de ciberdefensa: detección de alteraciones, sincronización remota segura, gestión de línea base y visualización de alertas. Se construyó utilizando únicamente librerías estándar de Python para mantener el enfoque en la lógica, la robustez y la reproducibilidad del resultado técnico.

La prueba de concepto está pensada para demostrar cómo un sistema defensor puede detectar indicadores de compromiso en un objetivo remoto sin instalar agentes en el host monitoreado. Se prioriza la separación de roles y la trazabilidad de cada cambio detectado.

% ===================== Objetivos =====================
\section{Objetivos}

\subsection{Objetivo general}

Desarrollar una PoC de ciberdefensa que detecte, registre y presente cambios en archivos críticos de un sistema remoto vulnerado.

\subsection{Objetivos específicos}

\begin{itemize}[leftmargin=1.5em]
    \item Implementar un sensor de integridad basado en hash SHA-256.
    \item Sincronizar archivos de Metasploitable2 hacia Ubuntu para su análisis.
    \item Generar alertas de creación, modificación y eliminación.
    \item Proveer una interfaz local accesible por navegador.
    \item Documentar el proceso, pruebas y resultados.
\end{itemize}

% ===================== Alcance =====================
\section{Alcance del proyecto}

El proyecto cubre:

\begin{itemize}[leftmargin=1.5em]
    \item Monitoreo remoto desde Ubuntu Desktop hacia Metasploitable2.
    \item Registro de alertas en base de datos SQLite.
    \item Interfaz web local en \url{http://127.0.0.1:8000}.
    \item Operación sin dependencias externas: solo Python estándar.
\end{itemize}

No incluye:

\begin{itemize}[leftmargin=1.5em]
    \item Detección de atacante por identidad.
    \item Autenticación inherente a la aplicación.
    \item Mecanismos de mitigación automática.
\end{itemize}

% ===================== Marco técnico =====================
\section{Marco técnico}

\subsection{Tecnologías usadas}

\begin{itemize}[leftmargin=1.5em]
    \item Python 3
    \item SQLite
    \item \texttt{scp} y \texttt{ssh} para sincronización remota
    \item Librerías estándar de Python: \texttt{os}, \texttt{sqlite3}, \texttt{hashlib}, \texttt{time}, \texttt{datetime}, \texttt{threading}, \texttt{subprocess}, \texttt{http.server}, \texttt{tkinter} (opcional)
\end{itemize}

\subsection{Lógica central del proyecto}

El proyecto se basa en las siguientes ideas principales:

\begin{itemize}[leftmargin=1.5em]
    \item El sistema defensor no monitorea directamente el sistema atacado; en su lugar, sincroniza una copia de la carpeta crítica desde el objetivo remoto para evitar el monitoreo local de Windows.
    \item La integridad se comprueba con hashes SHA-256 que se comparan con una línea base almacenada en SQLite.
    \item El proceso de detección distingue tres tipos de eventos: creación de archivos, modificación de archivos y eliminación de archivos.
    \item La detección se realiza de forma periódica o bajo demanda, y los resultados se muestran en una interfaz local accesible por navegador.
    \item El diseño enfatiza la simplicidad, la trazabilidad y la independencia de dependencias externas para un entorno académico.
\end{itemize}

\subsection{Arquitectura del sistema}

\begin{itemize}[leftmargin=1.5em]
    \item \textbf{Ubuntu Desktop} es el host defensor.
    \item \textbf{Metasploitable2} es el host monitoreado.
    \item \textbf{Kali Linux} se usa como actor atacante para modificar el objetivo.
    \item La carpeta remota \texttt{/home/msfadmin/carpeta\_critica} se sincroniza hacia \texttt{\textasciitilde/.fim\_poc/archivos\_criticos}.
\end{itemize}

\subsection{Base de datos}

La aplicación usa SQLite con dos tablas principales:

\begin{itemize}[leftmargin=1.5em]
    \item \textbf{inventario}: almacena \texttt{ruta\_archivo}, \texttt{hash\_seguro} y \texttt{ultima\_verificacion}.
    \item \textbf{alertas}: registra cambios con \texttt{ruta\_archivo}, \texttt{fecha\_hora}, \texttt{usuario}, \texttt{hash\_anterior}, \texttt{hash\_nuevo} y \texttt{tiempo\_deteccion\_ms}.
\end{itemize}

% ===================== Implementación =====================
\section{Implementación}

\subsection{Estructura de archivos}

\begin{itemize}[leftmargin=1.5em]
    \item \texttt{fim\_poc.py}: aplicación principal con lógica de línea base, escaneo, sincronización remota e interfaz web.
    \item \texttt{read\_alertas.py}: script auxiliar para consultar alertas desde la base de datos.
    \item \texttt{README.md}: documentación de uso del proyecto.
    \item \texttt{INFORME\_PROYECTO.md}: este informe.
\end{itemize}

\subsection{Desarrollo de la solución}

El código central se organiza en bloques funcionales claramente diferenciados. El archivo \texttt{fim\_poc.py} contiene:

\begin{itemize}[leftmargin=1.5em]
    \item Inicialización del entorno y base de datos con \texttt{init\_db()}.
    \item Creación y mantenimiento de la carpeta de vigilancia local con \texttt{ensure\_watch\_dir()}.
    \item Lectura y cálculo de hash SHA-256 en \texttt{sha256\_of\_file()}. Esta función procesa archivos por bloques para manejar ficheros grandes.
    \item Sincronización remota con \texttt{sincronizar\_remoto()}, que copia los datos remotos en un directorio temporal y luego actualiza el directorio local de observación.
    \item Gestión de la línea base con \texttt{establecer\_linea\_base()}, que guarda hashes iniciales en la tabla \texttt{inventario}.
    \item Verificación de integridad con \texttt{verificar\_integridad()}, que compara el estado actual con la línea base y registra alertas cuando los hashes cambian.
    \item Registro de alertas en la tabla \texttt{alertas} mediante \texttt{insertar\_alerta()}.
    \item Interfaz web local implementada con \texttt{BaseHTTPRequestHandler} y \texttt{ThreadingHTTPServer}.
    \item Un modo de ejecución headless y un componente de monitoreo continuo para escaneos periódicos.
\end{itemize}

\subsection{Algoritmo de verificación}

La función \texttt{verificar\_integridad()} ejecuta el algoritmo crítico de comparación:

\begin{enumerate}[leftmargin=1.5em]
    \item Se carga la línea base desde la tabla \texttt{inventario} y se normalizan las rutas de archivo para evitar discrepancias de formato.
    \item Si no existe línea base previa, se genera automáticamente con \texttt{establecer\_linea\_base()} y no se producen alertas.
    \item Se sincroniza el contenido remoto desde Metasploitable2 y solo si esta operación es exitosa se procede con el escaneo.
    \item Se recorre la copia local actual de \texttt{archivos\_criticos} y se calcula el hash actual de cada archivo.
    \item Para cada archivo:
    \begin{itemize}[leftmargin=1.5em]
        \item Si el archivo existe en la línea base y el hash es diferente, se inserta una alerta de modificación y se actualiza el inventario.
        \item Si el archivo existe en la línea base y el hash es igual, se actualiza la marca de última verificación sin generar alerta.
        \        \item Si el archivo no existía en la línea base, se inserta una alerta de creación y se agrega al inventario.
    \end{itemize}
    \item Se detectan eliminaciones calculando la diferencia entre los conjuntos de rutas base y actuales. Cada archivo eliminado genera una alerta y se borra del inventario.
\end{enumerate}

\subsection{Flujo de funcionamiento}

La implementación sigue un flujo claramente definido para asegurar que el monitoreo sea confiable y reproducible:

\begin{enumerate}[leftmargin=1.5em]
    \item \textbf{Inicialización:} el sistema crea el directorio de trabajo local en \texttt{\textasciitilde/.fim\_poc} y prepara la base de datos SQLite.
    \item \textbf{Establecer Línea Base:} se escanean los archivos presentes en el directorio local de vigilancia y se calculan hashes SHA-256. Estos hashes se guardan en la tabla \texttt{inventario} como referencia para futuras comparaciones.
    \item \textbf{Sincronizar Remoto:} antes de cada verificación, el sistema copia el contenido de la carpeta remota en Metasploitable2 hacia un directorio temporal local. El directorio local final se actualiza para reflejar el contenido remoto, incluyendo la eliminación de archivos que ya no existen en el objetivo.
    \item \textbf{Escanear Ahora:} el sistema recorre la copia local sincronizada, calcula el hash de cada archivo y compara contra la línea base.
    \item \textbf{Generación de alertas:} se registra un evento en la tabla \texttt{alertas} cuando se detecta cualquiera de los tres cambios:
    \begin{itemize}
        \item Archivo nuevo: aparece un archivo que no existía en la línea base.
        \item Archivo modificado: el hash actual difiere del hash almacenado.
        \item Archivo eliminado: un archivo que existía en la línea base ya no está en la copia local.
    \end{itemize}
    \item \textbf{Visualización y seguimiento:} los resultados se pueden consultar en la interfaz web, que presenta el número de archivos observados, alertas totales y el historial de eventos.
\end{enumerate}

\subsection{Sincronización remota}

La sincronización remota está diseñada para asegurar que Ubuntu Desktop observe el estado real de Metasploitable2 sin depender de archivos locales de Windows. La lógica implementada es:

\begin{itemize}[leftmargin=1.5em]
    \item Se utiliza \texttt{scp -r} para copiar recursivamente el contenido remoto.
    \item Se emplean opciones SSH compatibles con claves antiguas y con la versión de Metasploitable2:
    \begin{itemize}[leftmargin=1.5em]
        \item \texttt{-oHostKeyAlgorithms=+ssh-rsa}
        \item \texttt{-oPubkeyAcceptedAlgorithms=+ssh-rsa}
        \item \texttt{-oStrictHostKeyChecking=no}
        \item \texttt{-P 22}
    \end{itemize}
    \item El contenido remoto se copia primero a un directorio temporal local.
    \item Antes de mover los datos a la carpeta de monitoreo final, el sistema borra cualquier archivo local que ya no exista en el remoto, de forma que las eliminaciones remotas se reflejen correctamente.
    \item Si la sincronización falla, el escaneo no se ejecuta para evitar comparaciones con datos incompletos.
\end{itemize}

% ===================== Pruebas y validación =====================
\section{Pruebas y validación}

\subsection{Requisitos del entorno}

\begin{itemize}[leftmargin=1.5em]
    \item Ubuntu Desktop para ejecutar el PoC
    \item Metasploitable2 como objetivo monitorizado
    \item Kali Linux como atacante
    \item Python 3 instalado en Ubuntu
    \item \texttt{scp} disponible en Ubuntu
\end{itemize}

\subsection{Preparación de laboratorio}

En Metasploitable2:

\begin{lstlisting}[language=bash]
mkdir -p /home/msfadmin/carpeta_critica
echo "config_inicial" > /home/msfadmin/carpeta_critica/config.cfg
\end{lstlisting}

En Ubuntu:

\begin{lstlisting}[language=bash]
cd /ruta/al/proyecto
python3 fim_poc.py --web
\end{lstlisting}

\subsection{Pasos de prueba}

\begin{enumerate}[leftmargin=1.5em]
    \item Abrir la interfaz web en \url{http://127.0.0.1:8000}.
    \item Pulsar \textbf{Establecer Línea Base}.
    \item Pulsar \textbf{Sincronizar Remoto}.
    \item Pulsar \textbf{Escanear Ahora}.
    \item Desde Kali, ejecutar un cambio remoto vía SSH:
\end{enumerate}

\begin{lstlisting}[language=bash]
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -oStrictHostKeyChecking=no -p 22 msfadmin@10.0.2.4 "echo 'modificacion_maliciosa' >> /home/msfadmin/carpeta_critica/config.cfg"
\end{lstlisting}

\begin{enumerate}[leftmargin=1.5em, start=6]
    \item Volver a Ubuntu y ejecutar:
    \begin{itemize}
        \item Sincronizar Remoto
        \item Escanear Ahora
    \end{itemize}
\end{enumerate}

\subsection{Verificación de resultados}

El dashboard debe mostrar alertas en la tabla con cambios detectados. Las modificaciones deben registrar un hash anterior y un hash nuevo. Las eliminaciones deben aparecer con \texttt{hash\_nuevo = ELIMINADO}.

Adicionalmente, la prueba debe validar que:

\begin{itemize}[leftmargin=1.5em]
    \item Un escaneo posterior sin cambios no genere alertas adicionales.
    \item Las creaciones de archivos en Metasploitable2 se detecten tras la sincronización remota.
    \item Las eliminaciones remotas sean visibles en el conteo de archivos observados y en la tabla de alertas.
    \item Si la sincronización remota falla, el sistema indique el error y no proceda con un escaneo inválido.
\end{itemize}

% ===================== Cómo correr el proyecto =====================
\section{Cómo correr el proyecto}

\subsection{Interfaz web}

\begin{lstlisting}[language=bash]
python3 fim_poc.py --web
\end{lstlisting}

Abrir \url{http://127.0.0.1:8000} en el navegador.

\subsection{Modo CLI}

Línea base:

\begin{lstlisting}[language=bash]
python3 fim_poc.py --headless --action baseline
\end{lstlisting}

Escaneo:

\begin{lstlisting}[language=bash]
python3 fim_poc.py --headless --action scan
\end{lstlisting}

Sincronización remota:

\begin{lstlisting}[language=bash]
python3 fim_poc.py --headless --action sync
\end{lstlisting}

Monitoreo continuo:

\begin{lstlisting}[language=bash]
python3 fim_poc.py --headless --action monitor --monitor-interval 1.0
\end{lstlisting}

\subsection{Ejecución directa en caso de múltiples versiones de Python}

\begin{lstlisting}[language=bash]
python3 fim_poc.py
\end{lstlisting}

\subsection{Gestión de errores y robustez}

El sistema maneja condiciones de error importantes para evitar alertas falsas o datos incompletos:

\begin{itemize}[leftmargin=1.5em]
    \item Si \texttt{scp} falla, se registra el error y no se ejecuta el escaneo.
    \item Si no se puede leer un archivo durante el cálculo de hash, el sistema registra un evento de error de lectura.
    \item Las conexiones SQLite se crean por hilo para evitar conflictos de concurrencia.
    \item Las rutas se normalizan antes de compararlas para evitar falsos negativos por diferencias en separadores o mayúsculas/minúsculas.
\end{itemize}

% ===================== CRUD desde Kali =====================
\section{Cómo probar CRUD desde Kali}

Crear archivo:

\begin{lstlisting}[language=bash]
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -oStrictHostKeyChecking=no -p 22 msfadmin@10.0.2.4 "echo 'prueba' > /home/msfadmin/carpeta_critica/nuevo.txt"
\end{lstlisting}

Leer archivo:

\begin{lstlisting}[language=bash]
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -oStrictHostKeyChecking=no -p 22 msfadmin@10.0.2.4 "cat /home/msfadmin/carpeta_critica/nuevo.txt"
\end{lstlisting}

Modificar archivo:

\begin{lstlisting}[language=bash]
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -oStrictHostKeyChecking=no -p 22 msfadmin@10.0.2.4 "echo 'linea actualizada' >> /home/msfadmin/carpeta_critica/nuevo.txt"
\end{lstlisting}

Eliminar archivo:

\begin{lstlisting}[language=bash]
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -oStrictHostKeyChecking=no -p 22 msfadmin@10.0.2.4 "rm -f /home/msfadmin/carpeta_critica/nuevo.txt"
\end{lstlisting}

% ===================== Resultados esperados =====================
\section{Resultados esperados}

\begin{itemize}[leftmargin=1.5em]
    \item El sistema debe detectar cambios en archivos existentes.
    \item Debe registrar la creación de nuevos archivos.
    \item Debe detectar y registrar eliminaciones remotas.
    \item El conteo de archivos observados debe coincidir con la copia sincronizada desde Metasploitable2.
    \item No deben generarse alertas cuando no se realizan cambios reales.
    \item Los tiempos de detección deben ser consistentes y menores a 2 segundos para un conjunto pequeño de archivos.
    \item El proceso de sincronización debe ser capaz de manejar el fallo de \texttt{scp} sin corromper la línea base.
\end{itemize}

% ===================== Conclusiones =====================
\section{Conclusiones}

El proyecto demuestra una capa básica de ciberdefensa centrada en integridad de archivos. Aunque no identifica el actor (solo el evento), permite detectar alteraciones en un entorno remoto y validar la existencia de incidentes en la infraestructura monitorizada.

El diseño logra dos objetivos importantes:

\begin{itemize}[leftmargin=1.5em]
    \item Separar el rol de monitoreo defensivo (Ubuntu Desktop) del rol de objetivo comprometido (Metasploitable2).
    \item Proveer un mecanismo de detección confiable sin dependencias adicionales, lo que facilita su reproducción en un entorno académico.
\end{itemize}

La solución es especialmente útil para prácticas de ciberdefensa, ya que permite observar cómo cambios introducidos desde Kali Linux se reflejan en alertas y en la base de datos del defensor.

% ===================== Recomendaciones futuras =====================
\section{Recomendaciones futuras}

\begin{itemize}[leftmargin=1.5em]
    \item Agregar autenticación y control de acceso a la interfaz web.
    \item Registrar origen de cambios con más metadatos.
    \item Expandir la detección con firmas y análisis de comportamiento.
    \item Incluir una vista de historial de cambios y exportación de incidentes.
\end{itemize}

% ===================== Bibliografía =====================
\section{Bibliografía y referencias}

\begin{itemize}[leftmargin=1.5em]
    \item Python 3 Documentation
    \item SQLite Documentation
    \item Documentación de \texttt{ssh} y \texttt{scp}
\end{itemize}

\vspace{1cm}
\noindent\rule{\linewidth}{0.4pt}

\vspace{0.5cm}
\begin{tabular}{ll}
    \textbf{Archivo principal:} & \texttt{fim\_poc.py} \\[2pt]
    \textbf{Directorio de datos local:} & \texttt{\textasciitilde/.fim\_poc} \\[2pt]
    \textbf{Base de datos:} & \texttt{integridad\_monitores.db} \\[2pt]
    \textbf{Carpeta vigilada:} & \texttt{\textasciitilde/.fim\_poc/archivos\_criticos} \\[2pt]
    \textbf{Host monitoreado:} & \texttt{10.0.2.4} (Metasploitable2) \\[2pt]
    \textbf{Host atacante:} & \texttt{10.0.2.15} (Kali Linux) \\
\end{tabular}

\end{document}