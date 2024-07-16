cmake_minimum_required(VERSION 3.25)
project(app_smb)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(QT_VERSION 6)
    set(REQUIRED_LIBS Core Sql Widgets Gui Xml Network Core5Compat)
    set(REQUIRED_LIBS_QUALIFIED Qt6::Core Qt6::Sql Qt6::Widgets Qt6::Gui Qt6::Xml Qt6::Network Qt6::Core5Compat)
    set(MACOSX TRUE)

    add_library(app_smb SHARED
            module.cpp
            module.h
            smb_handler.cpp
            smb_handler.h)
    target_link_libraries(app_smb ${REQUIRED_LIBS_QUALIFIED})
    find_package(Boost 1.83.0 REQUIRED)
    find_package(Qt${QT_VERSION} COMPONENTS ${REQUIRED_LIBS} REQUIRED)
    target_link_libraries(${PROJECT_NAME} ${REQUIRED_LIBS_QUALIFIED})
endif ()
if (WIN32)
    set(CMAKE_PREFIX_PATH "C:/Qt/Qt5.14.2/5.14.2/msvc2017/bin/")
    set(QT_VERSION 5)
    set(REQUIRED_LIBS Core Sql Widgets Gui Network Xml WinExtras)
    set(REQUIRED_LIBS_QUALIFIED Qt5::Core Qt5::Sql Qt5::Widgets Qt5::Gui Qt5::Network Qt5::Xml Qt5::WinExtras)
    find_package(Boost 1.68.0 REQUIRED)
    INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})
    add_library(app_smb SHARED
            module.cpp
            module.h
            smb_handler.cpp
            smb_handler.h)
    #    target_link_libraries(app_smb c:/local/boost_1_68_0/stage/x86/lib/libboost_system-vc141-mt-gd-x32-1_68.lib)
    target_link_libraries(app_smb ${REQUIRED_LIBS_QUALIFIED})
    find_package(Qt${QT_VERSION} COMPONENTS ${REQUIRED_LIBS} REQUIRED)
    target_link_libraries(${PROJECT_NAME} ${REQUIRED_LIBS_QUALIFIED})
endif ()
